import json
import networkx as nx
from pyvis.network import Network
from build_data_driven_kg import load_evidence, construct_evidence_driven_graph

def main():
    print("[*] Ingesting Evidence and Constructing Verified CCD-Graph...")
    sast, dast = load_evidence("production_sast_cbom_evidence.json", "production_dast_cbom_evidence.json")
    G = construct_evidence_driven_graph(sast, dast)

    net = Network(height="950px", width="100%", bgcolor="#080c14", font_color="#ffffff", directed=True)
    
    # Optimized WebGL-friendly physics for 500+ nodes
    net.set_options("""
    {
      "nodes": {
        "font": { "size": 11, "face": "monospace", "color": "#ffffff" },
        "borderWidth": 1.5
      },
      "edges": {
        "smooth": { "type": "continuous", "roundness": 0.15 },
        "arrows": { "to": { "enabled": true, "scaleFactor": 0.5 } }
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -12000,
          "centralGravity": 0.25,
          "springLength": 95,
          "springStrength": 0.05,
          "damping": 0.75,
          "avoidOverlap": 0.2
        },
        "solver": "barnesHut"
      }
    }
    """)

    COLOR_MAP = {
        "SourceNode": "#22c55e",         # Green
        "CryptoPrimitiveNode": "#ef4444",# Crimson Red
        "BufferNode": "#f59e0b",          # Amber Orange
        "RuntimeEventNode": "#ec4899",   # Pink/Magenta Star
        "PQCTargetNode": "#a855f7",      # Purple Diamond
        "Other": "#64748b"
    }

    # Add Nodes
    for n, d in G.nodes(data=True):
        n_class = d.get("node_class", "Other")
        lbl = n.split("::")[-1]
        
        if n_class == "PQCTargetNode":
            color = COLOR_MAP["PQCTargetNode"]
            shape = "diamond"
            size = 26
        elif n_class == "RuntimeEventNode":
            color = COLOR_MAP["RuntimeEventNode"]
            shape = "star"
            size = 20
        elif n_class == "BufferNode":
            color = COLOR_MAP["BufferNode"]
            shape = "square"
            size = 14
        elif n_class == "CryptoPrimitiveNode":
            color = COLOR_MAP["CryptoPrimitiveNode"]
            shape = "dot"
            size = 18
        else:
            color = COLOR_MAP["SourceNode"]
            shape = "dot"
            size = 12

        tooltip = f"<b>{n}</b><br>Class: {n_class}<br>Provenance: {d.get('provenance', 'N/A')}"
        net.add_node(n, label=lbl, title=tooltip, color=color, size=size, shape=shape)

    # Add Edges (Distinguish Ground Truth vs. GNN Candidates)
    for u, v, d in G.edges(data=True):
        rel = d.get("relation", "")
        prov = d.get("provenance", "")
        
        if rel == "CANDIDATE_CROSS_LAYER_LINK":
            # GNN Candidates rendered as dashed, translucent gray
            e_color = "rgba(148, 163, 184, 0.25)"
            width = 0.8
            dashes = True
        elif rel == "SCOPED_BUFFER_DEFICIT_HAZARD":
            e_color = "#f43f5e"
            width = 2.0
            dashes = False
        elif rel == "RECOMMENDED_MIGRATION":
            e_color = "#a855f7"
            width = 2.0
            dashes = False
        elif "RUNTIME" in rel or "EXECUTES" in rel:
            e_color = "#ec4899"
            width = 1.5
            dashes = False
        else:
            e_color = "#3b82f6"
            width = 1.0
            dashes = False

        tooltip = f"Relation: {rel}<br>Provenance: {prov}"
        net.add_edge(u, v, title=tooltip, label=rel if width > 1.5 else "", color=e_color, width=width, dashes=dashes)

    output_html = "pqc_data_driven_kg.html"
    net.write_html(output_html)
    print(f"[+] Verified Full CCD-Graph successfully rendered to '{output_html}'.")

if __name__ == "__main__":
    main()
