import json
import networkx as nx
from pyvis.network import Network
from build_pqc_knowledge_graph import load_evidence, build_semantic_cbom_knowledge_graph

def main():
    print("[*] Loading Semantic CBOM Knowledge Graph...")
    sast_data, dast_data = load_evidence(
        "production_sast_cbom_evidence.json", 
        "production_dast_cbom_evidence.json"
    )
    G, dead_crypto, active_crypto = build_semantic_cbom_knowledge_graph(sast_data, dast_data)

    net = Network(height="950px", width="100%", bgcolor="#0a0e17", font_color="#ffffff", directed=True)
    
    net.set_options("""
    {
      "nodes": {
        "font": { "size": 14, "face": "monospace", "color": "#ffffff" },
        "borderWidth": 2
      },
      "edges": {
        "smooth": { "type": "cubicBezier", "roundness": 0.2 },
        "arrows": { "to": { "enabled": true, "scaleFactor": 0.8 } }
      },
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -220,
          "centralGravity": 0.02,
          "springLength": 200,
          "springStrength": 0.05,
          "damping": 0.55
        },
        "solver": "forceAtlas2Based"
      }
    }
    """)

    COLOR_MAP = {
        "Java_Switch": "#2ea043",         # Emerald Green
        "JNI_Bridge": "#388bfd",          # Royal Blue
        "Native_HSM": "#1f6feb",          # Indigo
        "Memory_Buffer": "#d29922",       # Amber Square
        "eBPF_DAST": "#db61a2",           # Pink Star
        "PQC_Target": "#a371f7",          # Purple Diamond
        "VULNERABLE": "#f85149"           # Crimson Red (Quantum Risk)
    }

    for n, d in G.nodes(data=True):
        n_class = d.get("node_class", "SourceNode")
        layer = d.get("layer", "Source_Module")
        risk = d.get("risk", "SAFE")
        lbl = d.get("label", n)

        if risk in ["VULNERABLE", "OVERFLOW_RISK"]:
            color = COLOR_MAP["VULNERABLE"]
            shape = "square" if n_class == "BufferNode" else "dot"
            size = 28
        elif n_class == "PQCNode":
            color = COLOR_MAP["PQC_Target"]
            shape = "diamond"
            size = 34
        elif n_class == "RuntimeNode":
            color = COLOR_MAP["eBPF_DAST"]
            shape = "star"
            size = 28
        elif n_class == "NetworkEndpointNode":
            color = "#00bcd4"
            shape = "hexagon"
            size = 26
        elif n_class == "BufferNode":
            color = COLOR_MAP["Memory_Buffer"]
            shape = "square"
            size = 24
        else:
            color = COLOR_MAP.get(layer, "#388bfd")
            shape = "dot"
            size = 26

        tooltip = f"<b>{n}</b><br>Class: {n_class}<br>Layer: {layer}<br>Risk: {risk}"
        net.add_node(n, label=lbl, title=tooltip, color=color, size=size, shape=shape)

    for u, v, d in G.edges(data=True):
        rel = d.get("relation", "")
        e_color = "#a371f7" if "PQC" in rel or "FALLBACK" in rel or "INCOMPATIBLE" in rel else "#db61a2" if "DYNAMIC" in rel or "TRAPPED" in rel else "#388bfd"
        width = 2.5 if ("PQC" in rel or "DYNAMIC" in rel or "INCOMPATIBLE" in rel) else 1.5
        net.add_edge(u, v, title=rel, label=rel, color=e_color, width=width)

    output_html = "pqc_cbom_knowledge_graph.html"
    net.write_html(output_html)
    print(f"[+] Knowledge Graph rendered with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges to '{output_html}'.")

if __name__ == "__main__":
    main()
