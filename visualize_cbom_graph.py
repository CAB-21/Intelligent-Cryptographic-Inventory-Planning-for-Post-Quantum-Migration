import json
import networkx as nx
from pyvis.network import Network
from build_pqc_knowledge_graph import load_evidence, construct_semantic_knowledge_graph

def generate_interactive_visualization():
    print("[*] Ingesting telemetry and building semantic multi-relational graph...")
    sast_data, dast_data = load_evidence(
        "production_sast_cbom_evidence.json", 
        "production_dast_cbom_evidence.json"
    )
    G = construct_semantic_knowledge_graph(sast_data, dast_data)

    print(f"[*] Compiling network visualization ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)...")
    net = Network(height="950px", width="100%", bgcolor="#121212", font_color="white", directed=True)
    net.force_atlas_2based(gravity=-60, central_gravity=0.015, spring_length=120, spring_strength=0.08, damping=0.5)

    COLOR_MAP = {
        "java_symbol": "#4CAF50",         # Green
        "native_symbol": "#2196F3",       # Blue
        "buffer": "#FF9800",              # Orange
        "runtime_invocation": "#E91E63",  # Magenta (eBPF)
        "file_container": "#616161",      # Dark Gray
        "pqc_target": "#00E676",          # Bright Mint (PQC Safe)
        "VULNERABLE": "#F44336"           # Red
    }

    for n, d in G.nodes(data=True):
        e_type = d.get("entity_type", "unknown")
        raw = d.get("raw_name", n)
        risk = d.get("quantum_risk", "SAFE")
        
        if risk == "VULNERABLE":
            color = COLOR_MAP["VULNERABLE"]
            size = 18
        elif e_type == "pqc_target":
            color = COLOR_MAP["pqc_target"]
            size = 28
            shape = "diamond"
        elif e_type == "runtime_invocation":
            color = COLOR_MAP["runtime_invocation"]
            size = 22
            shape = "star"
        elif e_type == "file_container":
            color = COLOR_MAP["file_container"]
            size = 10
            shape = "dot"
        else:
            color = COLOR_MAP.get(e_type, "#9E9E9E")
            size = 14
            shape = "dot"

        title_txt = f"<b>{n}</b><br>Type: {e_type}<br>Risk: {risk}"
        net.add_node(n, label=str(raw)[:25], title=title_txt, color=color, size=size)

    for u, v, d in G.edges(data=True):
        rel = d.get("relation", "")
        if "MIGRATION" in rel:
            edge_color = "#00E676"
            w = 2
        elif "TRIGGERS" in rel or "EXECUTION" in rel:
            edge_color = "#E91E63"
            w = 2
        elif "ALLOCATES" in rel:
            edge_color = "#FF9800"
            w = 1.5
        else:
            edge_color = "#333333"
            w = 0.5
        net.add_edge(u, v, color=edge_color, width=w, title=rel)

    output_html = "pqc_cbom_knowledge_graph.html"
    print(f"[*] Rendering to '{output_html}'...")
    net.write_html(output_html)
    print(f"[+] Complete! Open 'http://172.16.173.153:8080/pqc_cbom_knowledge_graph.html' to inspect.")

if __name__ == "__main__":
    generate_interactive_visualization()
