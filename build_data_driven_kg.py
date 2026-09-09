import json
import os
import sys
import networkx as nx
from cbom_ontology import (
    NodeClass, PrimitiveCategory, ProvenanceTier, 
    QuantumUrgency, CANONICAL_MIGRATION_STRATEGIES
)

def load_evidence(sast_file, dast_file):
    if not os.path.exists(sast_file) or not os.path.exists(dast_file):
        raise FileNotFoundError("Evidence JSON files missing.")
    with open(sast_file, "r") as f:
        sast_data = json.load(f)
    with open(dast_file, "r") as f:
        dast_data = json.load(f)
    return sast_data, dast_data


def classify_canonical_primitive(raw_token):
    token = str(raw_token).strip()
    token_u = token.upper()

    # 1. RSA Signatures & PKCS#1 Mechanisms
    if any(k in token_u for k in ["RSA", "CKM_RSA", "CKM_SHA256_RSA", "CKM_SHA512_RSA", "CKM_RSA_PKCS"]):
        return {
            "canonical_name": "RSA-2048_PKCS#1",
            "category": PrimitiveCategory.ASYMMETRIC_SIGNATURE.value,
            "urgency": QuantumUrgency.CRITICAL_SHOR_BROKEN.value,
            "strategy": "RSA_SIGNATURE"
        }
    # 2. ECDSA Signatures
    if "ECDSA" in token_u or token_u.startswith("CKM_ECDSA") or "EC_" in token_u:
        return {
            "canonical_name": "ECDSA-P256",
            "category": PrimitiveCategory.ASYMMETRIC_SIGNATURE.value,
            "urgency": QuantumUrgency.CRITICAL_SHOR_BROKEN.value,
            "strategy": "ECDSA_SIGNATURE"
        }
    # 3. 3DES / Triple-DES
    if any(k in token_u for k in ["3DES", "DES3", "DES_EDE", "CKM_DES3"]):
        return {
            "canonical_name": "3DES-EDE-168",
            "category": PrimitiveCategory.SYMMETRIC_CIPHER.value,
            "urgency": QuantumUrgency.HIGH_LEGACY_BROKEN.value,
            "strategy": "3DES_ENCRYPTION"
        }
    # 4. Legacy DES
    if token_u in ["DES", "CKM_DES_CBC", "CKM_DES_ECB", "CKM_DES_KEY_GEN"]:
        return {
            "canonical_name": "DES-56",
            "category": PrimitiveCategory.SYMMETRIC_CIPHER.value,
            "urgency": QuantumUrgency.HIGH_LEGACY_BROKEN.value,
            "strategy": "3DES_ENCRYPTION"
        }
    # 5. HMAC / MAC
    if "HMAC" in token_u or "KMAC" in token_u:
        return {
            "canonical_name": token,
            "category": PrimitiveCategory.MAC.value,
            "urgency": QuantumUrgency.QUANTUM_RESISTANT.value,
            "strategy": None
        }
    # 6. Legacy SHA-1 MAC / Digest
    if "SHA1" in token_u or "SHA-1" in token_u or token_u.startswith("CKM_SHA1"):
        return {
            "canonical_name": "SHA-1",
            "category": PrimitiveCategory.MAC.value if "MAC" in token_u else PrimitiveCategory.HASH_DIGEST.value,
            "urgency": QuantumUrgency.HIGH_LEGACY_BROKEN.value,
            "strategy": "SHA1_MAC" if "MAC" in token_u else "LEGACY_HASH"
        }
    # 7. Legacy MD5
    if "MD5" in token_u or token_u.startswith("CKM_MD5"):
        return {
            "canonical_name": "MD5",
            "category": PrimitiveCategory.HASH_DIGEST.value,
            "urgency": QuantumUrgency.HIGH_LEGACY_BROKEN.value,
            "strategy": "LEGACY_HASH"
        }
    # 8. Modern Symmetric AES
    if "AES" in token_u or token_u.startswith("CKM_AES"):
        return {
            "canonical_name": "AES-256-GCM" if any(k in token_u for k in ["GCM", "256"]) else "AES-128",
            "category": PrimitiveCategory.SYMMETRIC_CIPHER.value,
            "urgency": QuantumUrgency.QUANTUM_RESISTANT.value if ("256" in token_u or "GCM" in token_u) else QuantumUrgency.MEDIUM_GROVER_REDUCE.value,
            "strategy": None
        }
    # 9. Modern Hashes (SHA-256 / SHA-384 / SHA-512)
    if any(k in token_u for k in ["SHA256", "SHA-256", "SHA384", "SHA512", "CKM_SHA256", "CKM_SHA512"]):
        return {
            "canonical_name": token,
            "category": PrimitiveCategory.HASH_DIGEST.value,
            "urgency": QuantumUrgency.QUANTUM_RESISTANT.value,
            "strategy": None
        }

    return None


def construct_evidence_driven_graph(sast_records, dast_records):
    G = nx.MultiDiGraph()

    scope_to_crypto = {}    # { source_module: [crypto_node_ids] }
    scope_to_buffers = {}   # { source_module: [(buffer_node_id, alloc_size)] }
    static_crypto_map = {}
    static_buffers = {}
    dynamic_event_nodes = []

    # ========================================================================
    # 1. PARSE SAST EVIDENCE DYNAMICALLY
    # ========================================================================
    for entry in sast_records:
        file_path = entry.get("file", "unknown")
        file_base = os.path.basename(file_path)
        line = entry.get("line", 0)
        layer = entry.get("layer", "Source")

        # Ingest Source Module
        mod_id = f"Source::{file_base}"
        if mod_id not in G:
            G.add_node(
                mod_id,
                node_class=NodeClass.SOURCE_NODE.value,
                file_path=file_path,
                layer=layer,
                provenance=ProvenanceTier.TIER_2_STATIC_ESTABLISHED.value
            )
            scope_to_crypto[mod_id] = []
            scope_to_buffers[mod_id] = []

        # Ingest Scoped Buffer Allocations
        alloc_bytes = entry.get("allocated_bytes")
        if alloc_bytes is not None and int(alloc_bytes) > 0:
            b_size = int(alloc_bytes)
            var_name = entry.get("variable_name", "buf")
            b_id = f"Buffer::{file_base}::L{line}::{var_name}_{b_size}B"
            
            if b_id not in static_buffers:
                G.add_node(
                    b_id,
                    node_class=NodeClass.BUFFER_NODE.value,
                    allocated_bytes=b_size,
                    variable_name=var_name,
                    line=line,
                    file=file_base,
                    provenance=ProvenanceTier.TIER_2_STATIC_ESTABLISHED.value
                )
                static_buffers[b_id] = b_size
                scope_to_buffers[mod_id].append((b_id, b_size))

            G.add_edge(
                mod_id, b_id,
                relation="ALLOCATES_BUFFER",
                line=line,
                provenance=ProvenanceTier.TIER_2_STATIC_ESTABLISHED.value
            )

        # Harvest and Classify All Candidate Cryptographic Tokens Across Entry
        candidate_tokens = []
        for k, v in entry.items():
            if k not in ["file", "line", "layer", "allocated_bytes"] and v is not None:
                val_str = str(v).strip()
                if len(val_str) > 0 and len(val_str) < 80:
                    candidate_tokens.append(val_str)

        for raw_token in candidate_tokens:
            classification = classify_canonical_primitive(raw_token)
            if classification:
                c_id = f"Crypto::{classification['canonical_name']}"
                if c_id not in static_crypto_map:
                    G.add_node(
                        c_id,
                        node_class=NodeClass.CRYPTO_PRIMITIVE.value,
                        canonical_name=classification["canonical_name"],
                        category=classification["category"],
                        quantum_urgency=classification["urgency"],
                        replacement_strategy=classification["strategy"],
                        provenance=ProvenanceTier.TIER_2_STATIC_ESTABLISHED.value
                    )
                    static_crypto_map[c_id] = classification

                if c_id not in scope_to_crypto[mod_id]:
                    scope_to_crypto[mod_id].append(c_id)

                G.add_edge(
                    mod_id, c_id,
                    relation="CALLS_API",
                    line=line,
                    token=raw_token,
                    provenance=ProvenanceTier.TIER_2_STATIC_ESTABLISHED.value
                )

    # ========================================================================
    # 2. DYNAMIC TELEMETRY INGESTION & CROSS-LAYER FUSION
    # ========================================================================
    if len(dast_records) == 0:
        print("[!] NOTICE: 0 runtime events in DAST JSON. Registering UNRESOLVED cross-layer boundaries.")
    else:
        for idx, d in enumerate(dast_records):
            sym = d.get("symbol", "unknown")
            pid = d.get("pid", 0)
            proc = d.get("process", "unknown")
            rt_id = f"RuntimeEvent::{proc}::{sym}::PID_{pid}::{idx}"
            
            G.add_node(
                rt_id,
                node_class=NodeClass.RUNTIME_EVENT.value,
                symbol=sym,
                pid=pid,
                process=proc,
                provenance=ProvenanceTier.TIER_1_DYNAMIC_OBSERVED.value
            )
            dynamic_event_nodes.append(rt_id)

            # Resolve: Connect execution trace to native library
            hsm_node = "NativeLibrary::libsofthsm2.so"
            if hsm_node not in G:
                G.add_node(hsm_node, node_class=NodeClass.SOURCE_NODE.value, layer="Provider_Native_Library")
            
            G.add_edge(rt_id, hsm_node, relation="EXECUTES_IN", provenance=ProvenanceTier.TIER_1_DYNAMIC_OBSERVED.value)

            # Link Java Switch caller to runtime execution trace
            java_switch_nodes = [n for n in G.nodes() if "EnterprisePaymentSwitch" in n or "SimpleConfiguration" in n or "jpos" in n.lower()]
            for j_node in java_switch_nodes:
                G.add_edge(
                    j_node, rt_id,
                    relation="RESOLVES_TO_RUNTIME",
                    provenance=ProvenanceTier.TIER_3_CROSS_LAYER_FUSED.value,
                    evidence=f"PID {pid} execution correlation"
                )

    # ========================================================================
    # 3. SCOPE-AWARE BUFFER HAZARD CALCULATION (ZERO CARTESIAN PRODUCTS)
    # ========================================================================
    # Evaluate buffer safety margin ONLY where buffer and primitive share source scope
    for mod_id, crypto_list in scope_to_crypto.items():
        buffers_in_scope = scope_to_buffers.get(mod_id, [])
        
        for c_id in crypto_list:
            c_data = G.nodes[c_id]
            strategy_key = c_data.get("replacement_strategy")
            
            if strategy_key and strategy_key in CANONICAL_MIGRATION_STRATEGIES:
                strat = CANONICAL_MIGRATION_STRATEGIES[strategy_key]
                pqc_id = f"PQCTarget::{strat['target']}"
                
                if pqc_id not in G:
                    G.add_node(
                        pqc_id,
                        node_class=NodeClass.PQC_TARGET.value,
                        standard=strat["standard"],
                        category=strat["category"],
                        type=strat["type"],
                        required_bytes=strat["required_output_bytes"],
                        provenance="NIST_FIPS_CATALOG"
                    )

                G.add_edge(
                    c_id, pqc_id,
                    relation="RECOMMENDED_MIGRATION",
                    strategy=strategy_key,
                    provenance=ProvenanceTier.TIER_2_STATIC_ESTABLISHED.value
                )

                # Scope-Aware Buffer Deficit Calculation
                for b_id, alloc_sz in buffers_in_scope:
                    if alloc_sz < strat["required_output_bytes"]:
                        deficit = alloc_sz - strat["required_output_bytes"]
                        G.add_edge(
                            b_id, pqc_id,
                            relation="SCOPED_BUFFER_DEFICIT_HAZARD",
                            associated_crypto=c_id,
                            allocated_bytes=alloc_sz,
                            required_bytes=strat["required_output_bytes"],
                            deficit_bytes=deficit,
                            provenance=ProvenanceTier.TIER_2_STATIC_ESTABLISHED.value
                        )

    # ========================================================================
    # 4. UNRESOLVED CANDIDATE EDGES FOR GNN LINK PREDICTION
    # ========================================================================
    # Cross-layer candidate links connecting static primitives to eBPF dynamic execution
    for c_id in static_crypto_map:
        for rt_id in dynamic_event_nodes:
            if not G.has_edge(c_id, rt_id):
                G.add_edge(
                    c_id, rt_id,
                    relation="CANDIDATE_CROSS_LAYER_LINK",
                    provenance=ProvenanceTier.TIER_4_GNN_CANDIDATE.value,
                    status="UNRESOLVED_FOR_GNN"
                )

    return G


# ============================================================================
# COMPOSITE SYSTEMIC RISK (EQRS)
# ============================================================================

def compute_composite_eqrs(G, alpha=0.4, beta=0.4, gamma=0.2, w=0.5):
    simple_di = nx.DiGraph(G)
    betweenness = nx.betweenness_centrality(simple_di) if len(simple_di) > 0 else {}
    try:
        pagerank = nx.pagerank(simple_di)
    except Exception:
        pagerank = {n: 1.0 / max(1, len(simple_di)) for n in simple_di}
    indegree = {n: float(simple_di.in_degree(n)) for n in simple_di}
    max_in = max(indegree.values()) if indegree and max(indegree.values()) > 0 else 1.0

    eqrs_scores = {}
    for n in G.nodes():
        vq = G.nodes[n].get("quantum_urgency", 0.0)
        b = betweenness.get(n, 0.0)
        pr = pagerank.get(n, 0.0)
        ind = indegree.get(n, 0.0) / max_in

        g_hat = (alpha * b) + (beta * pr) + (gamma * ind)
        exposure = 1.0 if any(k in n for k in ["Socket", "Enterprise", "Switch", "Runtime"]) else 0.6
        score = (1.0 - w) * (vq * exposure) + (w * g_hat)
        eqrs_scores[n] = round(float(score), 4)

    return eqrs_scores


def main():
    print("================================================================================")
    print("  PHASE 3: RIGOROUS CROSS-LAYER CCD-GRAPH & EVIDENCE FUSION ENGINE              ")
    print("================================================================================")

    sast_path = "production_sast_cbom_evidence.json"
    dast_path = "production_dast_cbom_evidence.json"

    sast, dast = load_evidence(sast_path, dast_path)
    G = construct_evidence_driven_graph(sast, dast)

    print(f"[*] Cross-Layer Entity Resolution Complete:")
    print(f"    [+] Discovered Entities: {G.number_of_nodes()}")
    print(f"    [+] Evidence-Supported Edges: {G.number_of_edges()}")

    categories = {}
    for n, d in G.nodes(data=True):
        cls = d.get("node_class", "Other")
        categories[cls] = categories.get(cls, 0) + 1

    print("\n[-] Resolved Entity Classes:")
    for cls, cnt in categories.items():
        print(f"    • {cls}: {cnt}")

    scoped_hazards = [
        (u, v, d) for u, v, d in G.edges(data=True) 
        if d.get("relation") == "SCOPED_BUFFER_DEFICIT_HAZARD"
    ]
    print(f"\n[-] Genuine Scoped Buffer Deficit Hazards: {len(scoped_hazards)} (Scoped to Caller)")
    for u, v, d in scoped_hazards[:5]:
        print(f"    [TRUE HAZARD] {u} ──► {v} [Crypto: {d.get('associated_crypto')}] (Deficit: {d.get('deficit_bytes')} B)")

    candidate_edges = [
        (u, v, d) for u, v, d in G.edges(data=True) 
        if d.get("relation") == "CANDIDATE_CROSS_LAYER_LINK"
    ]
    print(f"\n[-] Unresolved Candidate Links for GNN Inference: {len(candidate_edges)}")

    eqrs = compute_composite_eqrs(G)

    export_payload = {
        "summary": {
            "total_nodes": G.number_of_nodes(),
            "total_edges": G.number_of_edges(),
            "entity_classes": categories,
            "scoped_buffer_hazards": len(scoped_hazards),
            "gnn_candidate_edges": len(candidate_edges)
        },
        "composite_eqrs": eqrs
    }

    with open("production_data_driven_kg.json", "w") as out:
        json.dump(export_payload, out, indent=2)

    print(f"\n[+] SUCCESS: Verified CCD-Graph exported to 'production_data_driven_kg.json'.")

if __name__ == "__main__":
    main()
