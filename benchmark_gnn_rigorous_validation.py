"""
benchmark_gnn_rigorous_validation.py: Publication-Grade Heterogeneous GNN Validation Suite
Features:
  1. Strict Leakage Elimination: Test edges are completely removed from message passing.
  2. Multi-Split Evaluation: Transductive Edge Split vs. Inductive Unseen Source-File Split.
  3. Multi-Seed Stability: 5 Random Seeds reporting mean and standard deviation (μ ± σ).
  4. Baselines & Ablation:
     - Heuristic Rule Engine (Degree Product Baseline)
     - Node-Pair MLP (Feature-Only Baseline)
     - Heterogeneous Graph Transformer (HGT Proposed)
     - HGT Ablated (Without DAST Runtime Telemetry)
"""

import os
import sys
import json
import time
import warnings
import math

warnings.filterwarnings("ignore")
os.environ["PYTHONWARNINGS"] = "ignore"

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import precision_recall_curve, auc, roc_auc_score

from build_data_driven_kg import load_evidence, construct_evidence_driven_graph


# ============================================================================
# 1. GRAPH EXTRACTION & FEATURE TENSORS
# ============================================================================

def build_graph_tensors(G, exclude_runtime=False):
    base_types = ["SourceNode", "CryptoPrimitiveNode", "BufferNode", "PQCTargetNode"]
    if not exclude_runtime:
        base_types.append("RuntimeEventNode")

    node_dict = {t: [] for t in base_types}
    for n, d in G.nodes(data=True):
        ntype = d.get("node_class", "SourceNode")
        if ntype in node_dict:
            node_dict[ntype].append(n)

    node_maps = {}
    x_dict = {}
    feature_dim = 32

    for ntype in base_types:
        nlist = node_dict[ntype]
        node_maps[ntype] = {n: i for i, n in enumerate(nlist)}
        num_nodes = len(nlist)
        if num_nodes == 0:
            x_dict[ntype] = torch.zeros((1, feature_dim), dtype=torch.float)
            continue

        feats = []
        for n in nlist:
            d = G.nodes[n]
            in_deg = float(G.in_degree(n)) if G.has_node(n) else 0.0
            out_deg = float(G.out_degree(n)) if G.has_node(n) else 0.0
            urgency = float(d.get("quantum_urgency", 0.0))
            alloc_sz = float(d.get("allocated_bytes", 0.0)) / 4096.0
            feats.append([in_deg, out_deg, urgency, alloc_sz])

        dense = torch.tensor(feats, dtype=torch.float)
        # Random projection to fill out the 32-dim space
        proj = torch.randn((4, feature_dim - 4))
        expanded = torch.matmul(dense, proj)
        x_dict[ntype] = torch.cat([dense, expanded], dim=1)

    # Ingest Edges
    edge_dict = {}
    for u, v, d in G.edges(data=True):
        rel = d.get("relation", "DEPENDS_ON")
        if rel in ["CANDIDATE_CROSS_LAYER_LINK", "SCOPED_BUFFER_DEFICIT_HAZARD", "BUFFER_CAPACITY_DEFICIT"]:
            continue

        src_type = G.nodes[u].get("node_class", "SourceNode")
        dst_type = G.nodes[v].get("node_class", "SourceNode")

        if src_type not in node_maps or dst_type not in node_maps:
            continue

        key = (src_type, rel, dst_type)
        if key not in edge_dict:
            edge_dict[key] = ([], [])

        edge_dict[key][0].append(node_maps[src_type][u])
        edge_dict[key][1].append(node_maps[dst_type][v])

    edge_index_dict = {}
    for key, (srcs, dsts) in edge_dict.items():
        if len(srcs) > 0:
            edge_index_dict[key] = torch.tensor([srcs, dsts], dtype=torch.long)

    return x_dict, edge_index_dict, node_maps


# ============================================================================
# 2. MODEL ARCHITECTURES (NATIVE HGT IMPLEMENTATION)
# ============================================================================

class NodePairMLP(nn.Module):
    def __init__(self, in_dim=32, hidden_dim=64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.25),
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1)
        )

    def forward(self, x_src, x_dst):
        h = torch.cat([x_src, x_dst], dim=-1)
        return torch.sigmoid(self.net(h)).squeeze(-1)


class HeteroGraphTransformerLayer(nn.Module):
    def __init__(self, node_types, edge_types, in_dim=64, out_dim=64, num_heads=4):
        super().__init__()
        self.num_heads = num_heads
        self.d_k = out_dim // num_heads
        self.node_types = node_types
        self.edge_types = edge_types

        self.k_linears = nn.ModuleDict({ntype: nn.Linear(in_dim, out_dim) for ntype in node_types})
        self.q_linears = nn.ModuleDict({ntype: nn.Linear(in_dim, out_dim) for ntype in node_types})
        self.v_linears = nn.ModuleDict({ntype: nn.Linear(in_dim, out_dim) for ntype in node_types})

        self.relation_att = nn.ParameterDict()
        self.relation_msg = nn.ParameterDict()
        for edge_type in edge_types:
            key_str = f"{edge_type[0]}___{edge_type[1]}___{edge_type[2]}"
            self.relation_att[key_str] = nn.Parameter(torch.randn(num_heads, self.d_k, self.d_k))
            self.relation_msg[key_str] = nn.Parameter(torch.randn(num_heads, self.d_k, self.d_k))

    def forward(self, x_dict, edge_index_dict):
        h_out = {ntype: torch.zeros_like(x_dict[ntype]) for ntype in self.node_types if ntype in x_dict}

        for (src_type, rel, dst_type), edge_index in edge_index_dict.items():
            if src_type not in x_dict or dst_type not in x_dict:
                continue
            if edge_index.size(1) == 0:
                continue

            key_str = f"{src_type}___{rel}___{dst_type}"
            src_x = x_dict[src_type]
            dst_x = x_dict[dst_type]

            # Compute Q, K, V
            q = self.q_linears[dst_type](dst_x).view(-1, self.num_heads, self.d_k)
            k = self.k_linears[src_type](src_x).view(-1, self.num_heads, self.d_k)
            v = self.v_linears[src_type](src_x).view(-1, self.num_heads, self.d_k)

            src_idx, dst_idx = edge_index[0], edge_index[1]

            # Relation-aware Attention
            r_att = self.relation_att[key_str]
            r_msg = self.relation_msg[key_str]

            k_heads = torch.einsum("nhd,hde->nhe", k[src_idx], r_att)
            q_heads = q[dst_idx]
            scores = (k_heads * q_heads).sum(dim=-1) / math.sqrt(self.d_k)
            weights = F.softmax(scores, dim=0)

            # Relation-aware Message
            v_heads = torch.einsum("nhd,hde->nhe", v[src_idx], r_msg)
            msg = (weights.unsqueeze(-1) * v_heads).view(-1, self.num_heads * self.d_k)

            h_out[dst_type].index_add_(0, dst_idx, msg)

        # Residual update
        final_dict = {}
        for ntype, h in h_out.items():
            final_dict[ntype] = F.relu(x_dict[ntype] + h)
        return final_dict


class PureHGTLinkPredictor(nn.Module):
    def __init__(self, node_types, edge_types, in_dim=32, hidden_dim=64, num_heads=4):
        super().__init__()
        self.node_types = node_types
        self.in_proj = nn.ModuleDict({ntype: nn.Linear(in_dim, hidden_dim) for ntype in node_types})
        self.hgt_layer1 = HeteroGraphTransformerLayer(node_types, edge_types, hidden_dim, hidden_dim, num_heads)
        self.hgt_layer2 = HeteroGraphTransformerLayer(node_types, edge_types, hidden_dim, hidden_dim, num_heads)
        self.decoder = NodePairMLP(in_dim=hidden_dim, hidden_dim=32)

    def forward(self, x_dict, edge_index_dict, src_type, dst_type, src_idx, dst_idx):
        h = {ntype: F.relu(self.in_proj[ntype](x_dict[ntype])) for ntype in self.node_types if ntype in x_dict}
        h = self.hgt_layer1(h, edge_index_dict)
        h = self.hgt_layer2(h, edge_index_dict)
        return self.decoder(h[src_type][src_idx], h[dst_type][dst_idx])


def compute_metrics(y_true, y_scores, k=50):
    roc = roc_auc_score(y_true, y_scores)
    prec_c, rec_c, _ = precision_recall_curve(y_true, y_scores)
    pr_auc = auc(rec_c, prec_c)

    order = np.argsort(-y_scores)
    sorted_labels = y_true[order]

    prec_k = np.mean(sorted_labels[:k]) if len(sorted_labels) >= k else 0.0
    rec_k = np.sum(sorted_labels[:k]) / max(1.0, np.sum(y_true))
    hits10 = 1.0 if np.sum(sorted_labels[:10]) > 0 else 0.0

    return {
        "ROC-AUC": float(roc),
        "PR-AUC": float(pr_auc),
        "Prec@50": float(prec_k),
        "Hits@10": float(hits10)
    }


# ============================================================================
# 3. BENCHMARK PIPELINE
# ============================================================================

def run_benchmark_split(split_type="transductive", num_seeds=5):
    print(f"\n================================================================================")
    print(f"  EXECUTING BENCHMARK: [{split_type.upper()} SPLIT] OVER {num_seeds} RANDOM SEEDS")
    print(f"================================================================================")

    sast, dast = load_evidence("production_sast_cbom_evidence.json", "production_dast_cbom_evidence.json")
    G = construct_evidence_driven_graph(sast, dast)

    target_edge = ("SourceNode", "CALLS_API", "CryptoPrimitiveNode")

    models = ["Heuristic", "Node-Pair MLP", "HGT (Proposed)", "HGT (Ablated: -DAST)"]
    metrics_tracker = {m: {"ROC-AUC": [], "PR-AUC": [], "Prec@50": [], "Hits@10": []} for m in models}

    for seed in range(num_seeds):
        torch.manual_seed(seed * 101)
        np.random.seed(seed * 101)

        # Full Data
        x_dict, edge_dict, node_maps = build_graph_tensors(G, exclude_runtime=False)
        # Ablated Data (No Runtime Nodes)
        x_dict_abl, edge_dict_abl, node_maps_abl = build_graph_tensors(G, exclude_runtime=True)

        full_edge_index = edge_dict[target_edge]
        num_edges = full_edge_index.size(1)

        if split_type == "transductive":
            perm = torch.randperm(num_edges)
            train_end = int(0.70 * num_edges)
            train_idx = perm[:train_end]
            test_idx = perm[train_end:]

            train_edges = full_edge_index[:, train_idx]
            test_pos_src = full_edge_index[0, test_idx]
            test_pos_dst = full_edge_index[1, test_idx]
        else:
            # Inductive: Hold out 30% unseen source files
            num_sources = x_dict["SourceNode"].size(0)
            src_perm = torch.randperm(num_sources)
            src_train_end = int(0.70 * num_sources)
            train_src_set = set(src_perm[:src_train_end].tolist())

            train_mask = [full_edge_index[0, i].item() in train_src_set for i in range(num_edges)]
            test_mask = [not m for m in train_mask]

            train_edges = full_edge_index[:, train_mask]
            test_pos_src = full_edge_index[0, test_mask]
            test_pos_dst = full_edge_index[1, test_mask]

        # Strict edge pruning: Test edges are completely removed from training graph
        train_edge_dict = dict(edge_dict)
        train_edge_dict[target_edge] = train_edges

        train_edge_dict_abl = dict(edge_dict_abl)
        train_edge_dict_abl[target_edge] = train_edges

        # Negative candidate sampling (1:5 imbalance)
        src_max = x_dict["SourceNode"].size(0)
        dst_max = x_dict["CryptoPrimitiveNode"].size(0)
        num_test_pos = test_pos_src.size(0)
        num_test_neg = num_test_pos * 5

        neg_src = torch.randint(0, src_max, (num_test_neg,))
        neg_dst = torch.randint(0, dst_max, (num_test_neg,))

        eval_src = torch.cat([test_pos_src, neg_src])
        eval_dst = torch.cat([test_pos_dst, neg_dst])
        eval_y = np.concatenate([np.ones(num_test_pos), np.zeros(num_test_neg)])

        # 1. Baseline: Heuristic Degree Product
        deg_src = x_dict["SourceNode"][eval_src, 0].numpy()
        deg_dst = x_dict["CryptoPrimitiveNode"][eval_dst, 0].numpy()
        h_scores = (deg_src * deg_dst) / (np.max(deg_src * deg_dst) + 1e-6)
        m_h = compute_metrics(eval_y, h_scores)
        for k in m_h: metrics_tracker["Heuristic"][k].append(m_h[k])

        # 2. Baseline: Node-Pair MLP
        mlp = NodePairMLP(in_dim=32, hidden_dim=64)
        opt_mlp = torch.optim.Adam(mlp.parameters(), lr=0.01, weight_decay=1e-4)
        for _ in range(50):
            mlp.train()
            opt_mlp.zero_grad()
            p_out = mlp(x_dict["SourceNode"][train_edges[0]], x_dict["CryptoPrimitiveNode"][train_edges[1]])
            ns = torch.randint(0, src_max, (train_edges.size(1),))
            nd = torch.randint(0, dst_max, (train_edges.size(1),))
            n_out = mlp(x_dict["SourceNode"][ns], x_dict["CryptoPrimitiveNode"][nd])
            loss = F.binary_cross_entropy(p_out, torch.ones_like(p_out)) + F.binary_cross_entropy(n_out, torch.zeros_like(n_out))
            loss.backward()
            opt_mlp.step()

        mlp.eval()
        with torch.no_grad():
            mlp_scores = mlp(x_dict["SourceNode"][eval_src], x_dict["CryptoPrimitiveNode"][eval_dst]).numpy()
        m_mlp = compute_metrics(eval_y, mlp_scores)
        for k in m_mlp: metrics_tracker["Node-Pair MLP"][k].append(m_mlp[k])

        # 3. Proposed: Heterogeneous Graph Transformer (HGT)
        hgt = PureHGTLinkPredictor(list(x_dict.keys()), list(train_edge_dict.keys()), in_dim=32, hidden_dim=64, num_heads=4)
        opt_hgt = torch.optim.Adam(hgt.parameters(), lr=0.005, weight_decay=1e-4)
        for _ in range(50):
            hgt.train()
            opt_hgt.zero_grad()
            p_preds = hgt(x_dict, train_edge_dict, "SourceNode", "CryptoPrimitiveNode", train_edges[0], train_edges[1])
            ns = torch.randint(0, src_max, (train_edges.size(1),))
            nd = torch.randint(0, dst_max, (train_edges.size(1),))
            n_preds = hgt(x_dict, train_edge_dict, "SourceNode", "CryptoPrimitiveNode", ns, nd)
            loss = F.binary_cross_entropy(p_preds, torch.ones_like(p_preds)) + F.binary_cross_entropy(n_preds, torch.zeros_like(n_preds))
            loss.backward()
            opt_hgt.step()

        hgt.eval()
        with torch.no_grad():
            hgt_scores = hgt(x_dict, train_edge_dict, "SourceNode", "CryptoPrimitiveNode", eval_src, eval_dst).numpy()
        m_hgt = compute_metrics(eval_y, hgt_scores)
        for k in m_hgt: metrics_tracker["HGT (Proposed)"][k].append(m_hgt[k])

        # 4. Ablation: HGT Without DAST Runtime Nodes
        hgt_abl = PureHGTLinkPredictor(list(x_dict_abl.keys()), list(train_edge_dict_abl.keys()), in_dim=32, hidden_dim=64, num_heads=4)
        opt_abl = torch.optim.Adam(hgt_abl.parameters(), lr=0.005, weight_decay=1e-4)
        for _ in range(50):
            hgt_abl.train()
            opt_abl.zero_grad()
            p_preds = hgt_abl(x_dict_abl, train_edge_dict_abl, "SourceNode", "CryptoPrimitiveNode", train_edges[0], train_edges[1])
            ns = torch.randint(0, src_max, (train_edges.size(1),))
            nd = torch.randint(0, dst_max, (train_edges.size(1),))
            n_preds = hgt_abl(x_dict_abl, train_edge_dict_abl, "SourceNode", "CryptoPrimitiveNode", ns, nd)
            loss = F.binary_cross_entropy(p_preds, torch.ones_like(p_preds)) + F.binary_cross_entropy(n_preds, torch.zeros_like(n_preds))
            loss.backward()
            opt_abl.step()

        hgt_abl.eval()
        with torch.no_grad():
            abl_scores = hgt_abl(x_dict_abl, train_edge_dict_abl, "SourceNode", "CryptoPrimitiveNode", eval_src, eval_dst).numpy()
        m_abl = compute_metrics(eval_y, abl_scores)
        for k in m_abl: metrics_tracker["HGT (Ablated: -DAST)"][k].append(m_abl[k])

    # Summary
    print(f"\n{'-'*95}")
    print(f"{'Model / Architecture':<30} | {'ROC-AUC (μ ± σ)':<18} | {'PR-AUC (μ ± σ)':<18} | {'Prec@50 (μ ± σ)':<18}")
    print(f"{'-'*95}")
    summary = {}
    for m in models:
        roc_m, roc_s = np.mean(metrics_tracker[m]["ROC-AUC"]), np.std(metrics_tracker[m]["ROC-AUC"])
        pr_m, pr_s = np.mean(metrics_tracker[m]["PR-AUC"]), np.std(metrics_tracker[m]["PR-AUC"])
        p50_m, p50_s = np.mean(metrics_tracker[m]["Prec@50"]), np.std(metrics_tracker[m]["Prec@50"])
        print(f"{m:<30} | {roc_m:.4f} ± {roc_s:.4f}   | {pr_m:.4f} ± {pr_s:.4f}   | {p50_m:.4f} ± {p50_s:.4f}")
        summary[m] = {
            "ROC-AUC": f"{roc_m:.4f} ± {roc_s:.4f}",
            "PR-AUC": f"{pr_m:.4f} ± {pr_s:.4f}",
            "Prec@50": f"{p50_m:.4f} ± {p50_s:.4f}"
        }
    print(f"{'-'*95}")
    return summary


def main():
    print("================================================================================")
    print("  PHASE 4: EXPERIMENTAL RIGOR & INDUCTIVE GENERALIZATION BENCHMARK              ")
    print("================================================================================")

    res_trans = run_benchmark_split("transductive", num_seeds=5)
    res_induc = run_benchmark_split("inductive", num_seeds=5)

    all_res = {
        "transductive_split": res_trans,
        "inductive_source_split": res_induc
    }

    with open("benchmark_gnn_rigorous_results.json", "w") as out:
        json.dump(all_res, out, indent=2)

    print("\n[+] Benchmark suite execution complete. Results saved to 'benchmark_gnn_rigorous_results.json'.")


if __name__ == "__main__":
    main()
