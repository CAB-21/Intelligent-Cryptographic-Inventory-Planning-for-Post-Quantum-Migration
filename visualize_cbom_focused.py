import json
import networkx as nx
from pyvis.network import Network
from build_pqc_knowledge_graph import build_enterprise_cbom_graph

def main():
    print("[*] Loading CBOM Knowledge Graph...")
    G = build_enterprise_cbom_graph("production_sast_cbom_evidence.json", "production_dast_cbom_evidence.json")

    net = Network(height="950px", width="100%", bgcolor="#0f141c", font_color="#f0f6fc", directed=True)
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
          "gravitationalConstant": -160,
          "centralGravity": 0.02,
          "springLength": 180,
          "springStrength": 0.05,
          "damping": 0.5
        },
        "solver": "forceAtlas2Based"
      }
    }
    """)

    COLOR_MAP = {
        "Java_Switch": "#2ea043",         # Green
        "JNI_Bridge": "#388bfd",          # Blue
        "Native_HSM": "#1f6feb",          # Dark Blue
        "Memory_Constraint": "#d29922",   # Orange
        "eBPF_Telemetry": "#db61a2",      # Magenta
        "PQC_Target": "#a371f7",          # Purple
        "VULNERABLE": "#f85149"           # Red
    }

    for n, d in G.nodes(data=True):
        layer = d.get("layer", "Unknown")
        risk = d.get("risk", "SAFE")
        node_type = d.get("type", "Entity")

        color = COLOR_MAP["VULNERABLE"] if risk in ["VULNERABLE", "OVERFLOW_RISK"] else COLOR_MAP.get(layer, "#8b949e")
        shape = "diamond" if layer == "PQC_Target" else "star" if layer == "eBPF_Telemetry" else "square" if layer == "Memory_Constraint" else "dot"
        size = 32 if layer == "PQC_Target" else 26 if layer == "eBPF_Telemetry" else 22

        tooltip = f"<b>{n}</b><br>Layer: {layer}<br>Type: {node_type}<br>Quantum Risk: {risk}"
        net.add_node(n, label=n.split("::")[-1], title=tooltip, color=color, size=size, shape=shape)

    for u, v, d in G.edges(data=True):
        rel = d.get("relation", "")
        e_color = "#a371f7" if "MIGRATION" in rel or "PQC" in rel else "#db61a2" if "DYNAMIC" in rel or "TRAPPED" in rel else "#388bfd"
        width = 2.5 if "MIGRATION" in rel or "DYNAMIC" in rel else 1.5
        net.add_edge(u, v, title=rel, label=rel, color=e_color, width=width)

    output_file = "pqc_cbom_knowledge_graph.html"
    net.write_html(output_file)
    print(f"[+] SUCCESS: Knowledge Graph rendered with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges to '{output_file}'.")

if __name__ == "__main__":
    main()
