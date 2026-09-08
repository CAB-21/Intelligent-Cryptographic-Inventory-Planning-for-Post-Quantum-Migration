import json
import networkx as nx
from pyvis.network import Network
from build_rigorous_cbom import load_evidence_files, build_rigorous_cbom_graph

def main():
    print("[*] Loading Rigorous Cryptographic Inventory Graph...")
    sast, dast = load_evidence_files("production_sast_cbom_evidence.json", "production_dast_cbom_evidence.json")
    G = build_rigorous_cbom_graph(sast, dast)

    net = Network(height="950px", width="100%", bgcolor="#080c14", font_color="#ffffff", directed=True)
    
    # Enhanced physics layout with strong repulsion to prevent text collision
    net.set_options("""
    {
      "nodes": {
        "font": { "size": 13, "face": "monospace", "color": "#ffffff" },
        "borderWidth": 2
      },
      "edges": {
        "smooth": { "type": "cubicBezier", "roundness": 0.28 },
        "arrows": { "to": { "enabled": true, "scaleFactor": 0.75 } },
        "font": { "size": 9, "face": "monospace", "color": "#94a3b8", "align": "middle", "strokeWidth": 2, "strokeColor": "#080c14" }
      },
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -380,
          "centralGravity": 0.015,
          "springLength": 260,
          "springStrength": 0.04,
          "damping": 0.7
        },
        "solver": "forceAtlas2Based"
      }
    }
    """)

    COLOR_MAP = {
        "CRITICAL": "#f85149",     # Crimson Red (Broken by Shor: RSA, PrivKey, Port 9999)
        "LEGACY": "#d97706",       # Amber Orange (3DES, SHA-1)
        "PQC_TARGET": "#a855f7",   # Purple Diamond (NIST Standard)
        "DYNAMIC_EBPF": "#ec4899", # Magenta Star (Kernel Trap)
        "APPLICATION": "#22c55e",  # Emerald Green (Java Switch Core)
        "HSM_ENGINE": "#2563eb",   # Indigo (SoftHSM2 Token)
        "SAFE_CIPHER": "#0ea5e9"   # Cyan/Blue (AES-256-GCM Session)
    }

    for n, d in G.nodes(data=True):
        n_class = d.get("node_class")
        urgency = d.get("quantum_urgency", 0.0)
        risk_lbl = d.get("risk_label", "SAFE")
        lbl = n.split("::")[-1]

        if n_class == "PQCTargetNode":
            color = COLOR_MAP["PQC_TARGET"]
            shape = "diamond"
            size = 36
        elif n_class == "RuntimeNode":
            color = COLOR_MAP["DYNAMIC_EBPF"]
            shape = "star"
            size = 28
        elif n_class == "BufferNode":
            color = COLOR_MAP["CRITICAL"] if urgency == 1.0 else COLOR_MAP["LEGACY"]
            shape = "square"
            size = 26
        elif "AES_256" in n:
            color = COLOR_MAP["SAFE_CIPHER"]
            shape = "dot"
            size = 24
        elif urgency == 1.0:
            color = COLOR_MAP["CRITICAL"]
            shape = "dot"
            size = 28
        elif urgency == 0.8:
            color = COLOR_MAP["LEGACY"]
            shape = "dot"
            size = 24
        elif "APP" in n:
            color = COLOR_MAP["APPLICATION"]
            shape = "dot"
            size = 28
        elif "HSM" in n:
            color = COLOR_MAP["HSM_ENGINE"]
            shape = "dot"
            size = 28
        else:
            color = "#64748b"
            shape = "dot"
            size = 22

        tooltip = f"<b>{n}</b><br>Class: {n_class}<br>Urgency: {urgency}<br>Risk: {risk_lbl}"
        net.add_node(n, label=lbl, title=tooltip, color=color, size=size, shape=shape)

    for u, v, d in G.edges(data=True):
        rel = d.get("relation", "")
        ev = d.get("evidence", {})
        tier = ev.get("confidence_tier", "Static")
        
        e_color = "#a855f7" if "MIGRATION" in rel or "TARGET" in rel or "DEFICIT" in rel else "#ec4899" if "DYNAMIC" in rel or "TRAPPED" in rel else "#3b82f6"
        width = 2.5 if "DEFICIT" in rel or "DYNAMIC" in rel else 1.5
        tooltip = f"Relation: {rel}<br>Provenance: {tier}"
        net.add_edge(u, v, title=tooltip, label=rel, color=e_color, width=width)

    output_html = "pqc_cbom_knowledge_graph.html"
    net.write_html(output_html)
    print(f"[+] Knowledge Graph successfully generated in '{output_html}'.")

if __name__ == "__main__":
    main()
