"""
benchmark_gnn_rigorous_validation.py
Phase 4: Publication-Grade Rigorous Benchmark & Inductive Generalization
Fixes Included:
1. Strict Disjoint Negative Sampling for both Transductive and Inductive splits (zero leakage).
2. Canonical Multi-Relational Edge Handling: keeps distinct (u, v, relation) triplets.
3. Training-Subgraph-Only Feature Computation: dynamically calculates degrees without global graph leakage.
4. Exact Multi-Relational Type Propagation: passes true edge relations into HGT convolution.
5. Exports detailed candidate-level predictions with ground-truth labels for auditing.
"""

import os
import json
import random
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc

from build_data_driven_kg import load_evidence, construct_evidence_driven_graph

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

def compute_metrics(y_true, y_pred):
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    
    if len(np.unique(y_true)) < 2:
        return 0.5, 0.0, 0.0
        
    roc = float(roc_auc_score(y_true, y_pred))
    p, r, _ = precision_recall_curve(y_true, y_pred)
    pr_auc = float(auc(r, p))
    
    k = min(50, len(y_pred))
    top_k_indices = np.argsort(y_pred)[::-1][:k]
    prec_at_50 = float(np.mean(y_true[top_k_indices])) if k > 0 else 0.0
    
    return roc, pr_auc, prec_at_50

class NodePairMLP(nn.Module):
    def __init__(self, in_dim, hidden_dim=64):
        super().__init__()
        self.fc1 = nn.Linear(in_dim * 2, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, 1)

    def forward(self, x_u, x_v):
        h = torch.cat([x_u, x_v], dim=-1)
        h = F.relu(self.fc1(h))
        return torch.sigmoid(self.fc2(h)).squeeze(-1)

class SimpleHGTLayer(nn.Module):
    def __init__(self, in_dim, out_dim, num_types=5, num_relations=5):
        super().__init__()
        self.out_dim = out_dim
        self.num_relations = num_relations
        self.W_q = nn.Parameter(torch.Tensor(num_types, in_dim, out_dim))
        self.W_k = nn.Parameter(torch.Tensor(num_types, in_dim, out_dim))
        self.W_v = nn.Parameter(torch.Tensor(num_types, in_dim, out_dim))
        self.R = nn.Parameter(torch.Tensor(num_relations, out_dim, out_dim))
        self.layer_norm = nn.LayerNorm(out_dim)
        self.reset_parameters()

    def reset_parameters(self):
        nn.init.xavier_uniform_(self.W_q)
        nn.init.xavier_uniform_(self.W_k)
        nn.init.xavier_uniform_(self.W_v)
        nn.init.xavier_uniform_(self.R)

    def forward(self, x, node_types, edge_index, edge_types):
        num_nodes = x.size(0)
        h_out = torch.zeros(num_nodes, self.out_dim, device=x.device)
        
        q = torch.zeros(num_nodes, self.out_dim, device=x.device)
        k = torch.zeros(num_nodes, self.out_dim, device=x.device)
        v = torch.zeros(num_nodes, self.out_dim, device=x.device)
        
        for t in range(self.W_q.size(0)):
            mask = (node_types == t)
            if mask.sum() > 0:
                q[mask] = torch.matmul(x[mask], self.W_q[t])
                k[mask] = torch.matmul(x[mask], self.W_k[t])
                v[mask] = torch.matmul(x[mask], self.W_v[t])

        if edge_index.size(1) > 0:
            src, dst = edge_index[0], edge_index[1]
            for r in range(self.R.size(0)):
                e_mask = (edge_types == r)
                if e_mask.sum() == 0:
                    continue
                e_src = src[e_mask]
                e_dst = dst[e_mask]
                
                k_r = torch.matmul(k[e_src], self.R[r])
                scores = (q[e_dst] * k_r).sum(dim=-1) / np.sqrt(self.out_dim)
                attn = torch.sigmoid(scores).unsqueeze(-1)
                
                msg = v[e_src] * attn
                h_out.index_add_(0, e_dst, msg)

        return self.layer_norm(h_out + q)

class HGTLinkPredictor(nn.Module):
    def __init__(self, in_dim, hidden_dim=64):
        super().__init__()
        self.hgt = SimpleHGTLayer(in_dim, hidden_dim)
        self.distmult_m = nn.Parameter(torch.ones(hidden_dim))

    def forward(self, x, node_types, edge_index, edge_types, eval_pairs):
        h = self.hgt(x, node_types, edge_index, edge_types)
        src = eval_pairs[:, 0]
        dst = eval_pairs[:, 1]
        score = (h[src] * self.distmult_m * h[dst]).sum(dim=-1)
        return torch.sigmoid(score), h

def prepare_base_graph():
    sast, dast = load_evidence("production_sast_cbom_evidence.json", "production_dast_cbom_evidence.json")
    G = construct_evidence_driven_graph(sast, dast)
    
    nodes = list(G.nodes())
    node_to_idx = {n: i for i, n in enumerate(nodes)}
    
    type_map = {"SourceNode": 0, "CryptoPrimitiveNode": 1, "BufferNode": 2, "PQCTargetNode": 3, "RuntimeEventNode": 4}
    node_types = []
    for n in nodes:
        cls = G.nodes[n].get("node_class", "SourceNode")
        node_types.append(type_map.get(cls, 0))
    node_types = torch.tensor(node_types, dtype=torch.long)
    
    urgency_vec = [float(G.nodes[n].get("quantum_urgency", 0.0)) for n in nodes]
    rel_map = {"CALLS_API": 0, "ALLOCATES_BUFFER": 1, "MIGRATES_TO": 2, "DEPENDS_ON": 3}
    
    # Retain distinct (u, v, r) triplets
    unique_triplets = set()
    target_edges_set = set()
    
    for u, v, d in G.edges(data=True):
        u_idx, v_idx = node_to_idx[u], node_to_idx[v]
        r = d.get("relation", "DEPENDS_ON")
        r_idx = rel_map.get(r, 3)
        
        unique_triplets.add((u_idx, v_idx, r_idx))
        if r == "CALLS_API":
            target_edges_set.add((u_idx, v_idx))

    all_edges = [(u, v) for (u, v, r) in unique_triplets]
    all_edge_types = [r for (u, v, r) in unique_triplets]
    target_edges = list(target_edges_set)

    return G, nodes, node_to_idx, node_types, urgency_vec, type_map, all_edges, all_edge_types, target_edges

def compute_split_features(num_nodes, node_types, urgency_vec, visible_edge_list):
    degrees = [0] * num_nodes
    for u, v in visible_edge_list:
        degrees[u] += 1
        degrees[v] += 1
        
    features = []
    for i in range(num_nodes):
        t = node_types[i].item()
        one_hot = [0.0] * 5
        one_hot[t] = 1.0
        norm_deg = [float(degrees[i]) / 50.0]
        urgency = [urgency_vec[i]]
        features.append(one_hot + norm_deg + urgency)
    return torch.tensor(features, dtype=torch.float)

def run_benchmark():
    print("================================================================================")
    print("  PHASE 4: EXPERIMENTAL RIGOR & DISJOINT INDUCTIVE/TRANSDUCTIVE BENCHMARK       ")
    print("================================================================================")

    G, nodes, node_to_idx, node_types, urgency_vec, type_map, all_edges, all_edge_types, target_edges = prepare_base_graph()
    num_nodes = len(nodes)
    
    source_indices = [node_to_idx[n] for n in nodes if G.nodes[n].get("node_class") == "SourceNode"]
    crypto_indices = [node_to_idx[n] for n in nodes if G.nodes[n].get("node_class") == "CryptoPrimitiveNode"]
    existing_target_set = set(target_edges)

    seeds = [42, 101, 2024, 7, 999]
    splits = ["transductive", "inductive"]
    models = ["Heuristic", "Node-Pair MLP", "HGT (Proposed)", "HGT (Ablated: -DAST)"]
    
    results = {split: {m: {"roc": [], "pr": [], "prec": []} for m in models} for split in splits}
    exported_predictions = []

    for split in splits:
        print(f"\n================================================================================")
        print(f"  EXECUTING BENCHMARK: [{split.upper()} SPLIT] OVER 5 RANDOM SEEDS")
        print(f"================================================================================")

        for seed_idx, seed in enumerate(seeds):
            set_seed(seed)
            
            if split == "transductive":
                shuffled_pos = random.sample(target_edges, len(target_edges))
                split_idx = int(0.8 * len(shuffled_pos))
                train_pos = shuffled_pos[:split_idx]
                test_pos = shuffled_pos[split_idx:]
                
                # STRICT TRANSDUCTIVE DISJOINT NEGATIVE SAMPLING
                all_possible_negs = [
                    (s, c) for s in source_indices for c in crypto_indices 
                    if (s, c) not in existing_target_set
                ]
                random.shuffle(all_possible_negs)
                
                n_train_neg = min(len(train_pos) * 2, len(all_possible_negs) // 2)
                n_test_neg = min(len(test_pos) * 2, len(all_possible_negs) - n_train_neg)
                
                train_neg = all_possible_negs[:n_train_neg]
                test_neg = all_possible_negs[n_train_neg:n_train_neg + n_test_neg]
                
                train_edge_indices = [i for i, e in enumerate(all_edges) if e not in set(test_pos)]
                train_edge_list = [all_edges[i] for i in train_edge_indices]
                train_edge_types = [all_edge_types[i] for i in train_edge_indices]

            else:
                # STRICT COLD-START INDUCTIVE PARTITIONING
                shuffled_src = random.sample(source_indices, len(source_indices))
                split_idx = int(0.8 * len(shuffled_src))
                train_src_set = set(shuffled_src[:split_idx])
                test_src_set = set(shuffled_src[split_idx:])
                
                train_pos = [(u, v) for (u, v) in target_edges if u in train_src_set]
                test_pos = [(u, v) for (u, v) in target_edges if u in test_src_set]

                # STRICT NEGATIVE POOL DISJUNCTION (zero test sources in train negatives)
                train_possible_negs = [
                    (s, c) for s in train_src_set for c in crypto_indices
                    if (s, c) not in existing_target_set
                ]
                test_possible_negs = [
                    (s, c) for s in test_src_set for c in crypto_indices
                    if (s, c) not in existing_target_set
                ]

                train_neg = random.sample(train_possible_negs, min(len(train_pos) * 2, len(train_possible_negs)))
                test_neg = random.sample(test_possible_negs, min(len(test_pos) * 2, len(test_possible_negs)))

                # Strictly isolate graph topology: Test sources cannot pass messages during training
                train_edge_indices = [
                    i for i, (u, v) in enumerate(all_edges) 
                    if (u not in test_src_set and v not in test_src_set) and (u, v) not in set(test_pos)
                ]
                train_edge_list = [all_edges[i] for i in train_edge_indices]
                train_edge_types = [all_edge_types[i] for i in train_edge_indices]

            # DYNAMIC DEGREE COMPUTATION (Calculated strictly on training graph)
            x_train = compute_split_features(num_nodes, node_types, urgency_vec, train_edge_list)

            # PyTorch Tensors
            edge_index = torch.tensor(train_edge_list, dtype=torch.long).t().contiguous()
            edge_types = torch.tensor(train_edge_types, dtype=torch.long)

            train_pairs = train_pos + train_neg
            train_labels = [1.0] * len(train_pos) + [0.0] * len(train_neg)
            train_pairs_tensor = torch.tensor(train_pairs, dtype=torch.long)
            train_labels_tensor = torch.tensor(train_labels, dtype=torch.float)

            test_pairs = test_pos + test_neg
            test_labels = [1] * len(test_pos) + [0] * len(test_neg)
            test_pairs_tensor = torch.tensor(test_pairs, dtype=torch.long)

            # ---------------- Model Evaluation ----------------
            for m in models:
                if m == "Heuristic":
                    degrees = [0] * num_nodes
                    for u, v in train_edge_list:
                        degrees[u] += 1
                        degrees[v] += 1
                    scores = [float(degrees[u]) / 50.0 for (u, v) in test_pairs]

                elif m == "Node-Pair MLP":
                    mlp = NodePairMLP(x_train.size(1))
                    optimizer = torch.optim.Adam(mlp.parameters(), lr=0.01, weight_decay=1e-4)
                    criterion = nn.BCELoss()

                    mlp.train()
                    for epoch in range(50):
                        optimizer.zero_grad()
                        pred = mlp(x_train[train_pairs_tensor[:, 0]], x_train[train_pairs_tensor[:, 1]])
                        loss = criterion(pred, train_labels_tensor)
                        loss.backward()
                        optimizer.step()

                    mlp.eval()
                    with torch.no_grad():
                        scores = mlp(x_train[test_pairs_tensor[:, 0]], x_train[test_pairs_tensor[:, 1]]).numpy().tolist()

                elif "HGT" in m:
                    hgt_model = HGTLinkPredictor(x_train.size(1))
                    optimizer = torch.optim.Adam(hgt_model.parameters(), lr=0.01, weight_decay=1e-4)
                    criterion = nn.BCELoss()

                    cur_x = x_train.clone()
                    if "-DAST" in m:
                        cur_x[node_types == 4] = 0.0

                    hgt_model.train()
                    for epoch in range(60):
                        optimizer.zero_grad()
                        pred, _ = hgt_model(cur_x, node_types, edge_index, edge_types, train_pairs_tensor)
                        loss = criterion(pred, train_labels_tensor)
                        loss.backward()
                        optimizer.step()

                    hgt_model.eval()
                    with torch.no_grad():
                        raw_scores, _ = hgt_model(cur_x, node_types, edge_index, edge_types, test_pairs_tensor)
                        scores = raw_scores.numpy().tolist()

                        if split == "inductive" and m == "HGT (Proposed)" and seed_idx == 0:
                            exported_predictions = []
                            for idx, pair in enumerate(test_pairs):
                                score = float(scores[idx])
                                label = int(test_labels[idx])
                                exported_predictions.append({
                                    "source": nodes[pair[0]],
                                    "relation": "CALLS_API",
                                    "target": nodes[pair[1]],
                                    "hgt_score": round(score, 4),
                                    "ground_truth": bool(label == 1),
                                    "was_in_training_graph": False,
                                    "split": "cold_start_inductive_test",
                                    "provenance": "TIER_4_GNN_CANDIDATE" if score >= 0.85 else "UNPROMOTED_CANDIDATE"
                                })

                roc, pr, prec = compute_metrics(test_labels, scores)
                results[split][m]["roc"].append(roc)
                results[split][m]["pr"].append(pr)
                results[split][m]["prec"].append(prec)

        print(f"{'Model / Architecture':<28} | {'ROC-AUC (μ ± σ)':<20} | {'PR-AUC (μ ± σ)':<20} | {'Prec@50 (μ ± σ)'}")
        print("-" * 95)
        for m in models:
            roc_m = f"{np.mean(results[split][m]['roc']):.4f} ± {np.std(results[split][m]['roc']):.4f}"
            pr_m = f"{np.mean(results[split][m]['pr']):.4f} ± {np.std(results[split][m]['pr']):.4f}"
            prec_m = f"{np.mean(results[split][m]['prec']):.4f} ± {np.std(results[split][m]['prec']):.4f}"
            print(f"{m:<28} | {roc_m:<20} | {pr_m:<20} | {prec_m}")

    out_preds_file = "hgt_inductive_predictions.json"
    with open(out_preds_file, "w") as f:
        json.dump(exported_predictions, f, indent=2)
    print(f"\n[+] Cold-start inductive candidate predictions saved to '{out_preds_file}' ({len(exported_predictions)} pairs).")

    summary_file = "benchmark_gnn_rigorous_results.json"
    serializable = {}
    for sp in results:
        serializable[sp] = {}
        for m in results[sp]:
            serializable[sp][m] = {
                "roc_mean": float(np.mean(results[sp][m]["roc"])),
                "roc_std": float(np.std(results[sp][m]["roc"])),
                "pr_mean": float(np.mean(results[sp][m]["pr"])),
                "pr_std": float(np.std(results[sp][m]["pr"])),
                "prec_mean": float(np.mean(results[sp][m]["prec"])),
                "prec_std": float(np.std(results[sp][m]["prec"]))
            }
    with open(summary_file, "w") as f:
        json.dump(serializable, f, indent=2)
    print(f"[+] Summary statistics saved to '{summary_file}'.")

if __name__ == "__main__":
    run_benchmark()
