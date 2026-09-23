"""
compute_migration_dag.py: Phase 5 - Directed Acyclic Graph (DAG) Migration Scheduler
Computes leaf-to-root topological ordering for phased PQC replacement.
"""

import json
import networkx as nx
from build_data_driven_kg import load_evidence, construct_evidence_driven_graph

def main():
    print("================================================================================")
    print("  PHASE 5: COMPUTING TOPOLOGICAL PQC MIGRATION SCHEDULE                         ")
    print("================================================================================")

    sast, dast = load_evidence("production_sast_cbom_evidence.json", "production_dast_cbom_evidence.json")
    G = construct_evidence_driven_graph(sast, dast)

    # Build Dependency DAG focusing on Source Files and Cryptographic Providers
    dag = nx.DiGraph()
    for u, v, d in G.edges(data=True):
        rel = d.get("relation", "")
        # Dependency edges dictate migration precedence
        if rel in ["DEPENDS_ON", "CALLS_API", "ALLOCATES_BUFFER"]:
            dag.add_edge(u, v)

    # Break accidental circular references if any (SCC resolution for topological sort)
    sccs = list(nx.strongly_connected_components(dag))
    cycles_broken = 0
    for scc in sccs:
        if len(scc) > 1:
            nodes = list(scc)
            for i in range(len(nodes) - 1):
                if dag.has_edge(nodes[i+1], nodes[i]):
                    dag.remove_edge(nodes[i+1], nodes[i])
                    cycles_broken += 1

    print(f"[*] Built Migration DAG: {dag.number_of_nodes()} Nodes, {dag.number_of_edges()} Edges")
    if cycles_broken > 0:
        print(f"    [!] Resolved {cycles_broken} circular dependencies for acyclic sort")

    # Perform Topological Sort (Reverse post-order gives safe bottom-up migration order)
    try:
        topo_order = list(nx.topological_sort(dag))
        topo_order.reverse()  # Bottom-up (leaf-first)
    except nx.NetworkXUnfeasible:
        print("[!] Cycle detected; falling back to pagerank-based dependency depth ordering.")
        ranks = nx.pagerank(dag)
        topo_order = sorted(ranks.keys(), key=lambda x: ranks[x])

    # Classify by migration tiers
    migration_phases = {
        "Phase_1_Leaf_Primitives_And_Buffers": [],
        "Phase_2_Provider_Wrappers_And_C_Libraries": [],
        "Phase_3_Application_Orchestrators_And_Gateways": []
    }

    for node in topo_order:
        data = G.nodes.get(node, {})
        nclass = data.get("node_class", "SourceNode")
        if nclass in ["CryptoPrimitiveNode", "BufferNode", "PQCTargetNode"]:
            migration_phases["Phase_1_Leaf_Primitives_And_Buffers"].append(node)
        elif "libsofthsm" in node or "pkcs11" in node or ".so" in node or ".cpp" in node or ".h" in node:
            migration_phases["Phase_2_Provider_Wrappers_And_C_Libraries"].append(node)
        else:
            migration_phases["Phase_3_Application_Orchestrators_And_Gateways"].append(node)

    print("\n--- MIGRATION PRECEDENCE PLAN ---")
    print(f"1. Low-Level Leaves (Primitives/Buffers): {len(migration_phases['Phase_1_Leaf_Primitives_And_Buffers'])} targets")
    print(f"2. Native C/C++ Provider Libraries:      {len(migration_phases['Phase_2_Provider_Wrappers_And_C_Libraries'])} modules")
    print(f"3. High-Level Java Switch Gateways:      {len(migration_phases['Phase_3_Application_Orchestrators_And_Gateways'])} orchestrators")

    out_file = "pqc_migration_topological_schedule.json"
    with open(out_file, "w") as f:
        json.dump(migration_phases, f, indent=2)

    print(f"\n[+] Topological migration schedule exported to '{out_file}'.")

if __name__ == "__main__":
    main()
