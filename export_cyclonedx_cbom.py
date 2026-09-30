"""
export_cyclonedx_cbom.py: Phase 6 - Standardized CycloneDX v1.6 CBOM Serializer
Translates the Cross-Layer Cryptographic Dependency Graph (CCD-Graph),
scoped buffer capacity deficits, and empirical eBPF latencies into an official
CycloneDX v1.6 Cryptographic Bill of Materials (CBOM) JSON document.
"""

import os
import json
import uuid
from datetime import datetime, timezone
import networkx as nx

from build_data_driven_kg import load_evidence, construct_evidence_driven_graph

def infer_replacement_from_primitive(algo_name):
    """Fallback resolver based on NIST/CNSA 2.0 cryptographic standards."""
    name_upper = algo_name.upper()
    if any(k in name_upper for k in ["RSA", "ECDSA", "DSA", "SIGN"]):
        return "ML-DSA-65 (NIST FIPS 204)"
    elif any(k in name_upper for k in ["DH", "ECDH", "KEM", "WRAP"]):
        return "ML-KEM-768 (NIST FIPS 203)"
    elif any(k in name_upper for k in ["AES", "DES", "3DES"]):
        return "AES-256-GCM (CNSA 2.0)"
    elif any(k in name_upper for k in ["SHA", "MD5", "RIPEMD", "GOSTR"]):
        return "SHA3-512 (NIST FIPS 202)"
    return "AES-256-GCM / ML-KEM-768"

def generate_cyclonedx_cbom():
    print("================================================================================")
    print("  PHASE 6: CYCLONEDX v1.6 CRYPTOGRAPHIC BILL OF MATERIALS (CBOM) EXPORTER        ")
    print("================================================================================")

    # 1. Load fused Knowledge Graph
    sast, dast = load_evidence("production_sast_cbom_evidence.json", "production_dast_cbom_evidence.json")
    G = construct_evidence_driven_graph(sast, dast)
    print(f"[*] Ingested CCD-Graph: {G.number_of_nodes()} Entities, {G.number_of_edges()} Edges")

    # Pre-compute MIGRATES_TO mappings directly from Graph Edges
    migrates_to_map = {}
    for u, v, d in G.edges(data=True):
        if d.get("relation") == "MIGRATES_TO":
            # Extract target name (strip 'PQCTarget::' prefix if present)
            target_name = v.replace("PQCTarget::", "")
            migrates_to_map[u] = target_name

    # 2. Load eBPF Latency Telemetry if available
    latency_profile = {}
    if os.path.exists("crypto_execution_latency_profile.json"):
        with open("crypto_execution_latency_profile.json", "r") as f:
            latency_profile = json.load(f)
        print("[*] Integrated Authentic eBPF Dynamic Latency Telemetry")

    # 3. Base CycloneDX v1.6 Metadata Structure
    cbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Cross-Layer Cryptographic Dependency Graph (CCD-Graph)",
                        "version": "1.0.0",
                        "description": "Multi-modal SAST/DAST evidence fusion with GNN relational inference engine"
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "Core Banking Switch & PKCS#11 Security Stack",
                "version": "2.4.0",
                "description": "Hybrid Java ISO-8583 switch interfacing with SoftHSM2 native cryptographic engine"
            }
        },
        "components": [],
        "dependencies": []
    }

    # 4. Map Knowledge Graph Nodes to CycloneDX Components
    node_to_bom_ref = {}

    for node_id, data in G.nodes(data=True):
        nclass = data.get("node_class", "SourceNode")
        bom_ref = f"cbom-{uuid.uuid5(uuid.NAMESPACE_DNS, str(node_id))}"
        node_to_bom_ref[node_id] = bom_ref

        if nclass == "CryptoPrimitiveNode":
            algo_name = data.get("canonical_name") or data.get("name", node_id)
            urgency = data.get("quantum_urgency", 0.0)
            algo_upper = algo_name.upper()

            # Determine primitive type
            if any(k in algo_upper for k in ["SIGN", "RSA", "DSA", "ECDSA"]):
                prim_type = "signature"
                crypto_funcs = ["sign", "verify"]
            elif any(k in algo_upper for k in ["SHA", "MD5", "RIPEMD", "GOSTR", "DIGEST"]):
                prim_type = "message-digest"
                crypto_funcs = ["digest"]
            elif any(k in algo_upper for k in ["DH", "ECDH", "KEM"]):
                prim_type = "key-exchange"
                crypto_funcs = ["key-agreement"]
            else:
                prim_type = "block-cipher"
                crypto_funcs = ["encrypt", "decrypt"]

            # Resolve PQC replacement: Priority 1 = MIGRATES_TO graph edge, Priority 2 = Standard mapping
            target_replacement = migrates_to_map.get(node_id) or infer_replacement_from_primitive(algo_name)

            comp = {
                "type": "cryptographic-asset",
                "bom-ref": bom_ref,
                "name": algo_name,
                "description": f"Cryptographic primitive detected via {data.get('provenance', 'SAST')}",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": prim_type,
                        "parameterSetIdentifier": str(data.get("key_size_bits", "N/A")),
                        "executionEnvironment": "hardware-security-module" if "libsofthsm" in str(data) else "software-container",
                        "cryptoFunctions": crypto_funcs
                    },
                    "oid": data.get("oid", "unknown")
                },
                "properties": [
                    {"name": "pqc:quantum_urgency_score", "value": str(urgency)},
                    {"name": "pqc:epistemic_provenance", "value": data.get("provenance", "TIER_2_AST_STATIC")},
                    {"name": "pqc:replacement_target", "value": target_replacement}
                ]
            }

            # Attach measured eBPF signing latency to asymmetric signing primitives
            if prim_type == "signature" and "signing_pipeline_latency_us" in latency_profile:
                comp["properties"].append({
                    "name": "dast:signing_pipeline_latency_us",
                    "value": str(latency_profile["signing_pipeline_latency_us"])
                })

            cbom["components"].append(comp)

        elif nclass == "BufferNode":
            alloc_bytes = data.get("allocated_bytes", 0)
            comp = {
                "type": "data",
                "bom-ref": bom_ref,
                "name": data.get("name", node_id),
                "description": f"Fixed stack/heap memory allocation buffer at {data.get('source_location', 'unknown')}",
                "properties": [
                    {"name": "memory:allocated_bytes", "value": str(alloc_bytes)},
                    {"name": "memory:scope", "value": data.get("scope", "local")}
                ]
            }
            cbom["components"].append(comp)

        elif nclass == "PQCTargetNode":
            comp = {
                "type": "cryptographic-asset",
                "bom-ref": bom_ref,
                "name": data.get("name", node_id),
                "description": "NIST FIPS 203/204/205 Post-Quantum Replacement Standard",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "post-quantum-primitive",
                        "parameterSetIdentifier": data.get("nist_round", "FIPS-Standardized")
                    }
                },
                "properties": [
                    {"name": "pqc:standard_compliance", "value": data.get("compliance_standard", "NIST-PQC")}
                ]
            }
            cbom["components"].append(comp)

        else:
            comp = {
                "type": "application" if ".java" in str(node_id) else "library",
                "bom-ref": bom_ref,
                "name": os.path.basename(str(node_id)),
                "description": f"Source module: {node_id}",
                "properties": [
                    {"name": "source:path", "value": str(node_id)},
                    {"name": "source:language", "value": "Java" if ".java" in str(node_id) else "C/C++"}
                ]
            }
            cbom["components"].append(comp)

    # 5. Map Knowledge Graph Edges to CycloneDX Dependencies
    deficit_count = 0
    for u, v, d in G.edges(data=True):
        if u not in node_to_bom_ref or v not in node_to_bom_ref:
            continue
        rel = d.get("relation", "DEPENDS_ON")
        
        dep_entry = {
            "ref": node_to_bom_ref[u],
            "dependsOn": [node_to_bom_ref[v]],
            "properties": [
                {"name": "relation:type", "value": rel},
                {"name": "relation:provenance", "value": d.get("provenance", "STATIC")}
            ]
        }

        if rel in ["BUFFER_CAPACITY_DEFICIT", "SCOPED_BUFFER_DEFICIT_HAZARD"]:
            deficit_count += 1
            dep_entry["properties"].extend([
                {"name": "pqc:hazard_type", "value": "BUFFER_CAPACITY_DEFICIT"},
                {"name": "pqc:margin_deficit_bytes", "value": str(d.get("deficit_bytes", d.get("deficit", "N/A")))}
            ])

        cbom["dependencies"].append(dep_entry)

    # 6. Export Serialized Document
    out_file = "cyclonedx_v1.6_cbom.json"
    with open(out_file, "w") as f:
        json.dump(cbom, f, indent=2)

    print(f"\n[+] Serialization Complete:")
    print(f"    ├── Output Specification: CycloneDX v1.6 JSON Schema")
    print(f"    ├── Serialized Components: {len(cbom['components'])} assets")
    print(f"    ├── Serialized Dependencies: {len(cbom['dependencies'])} links")
    print(f"    ├── Flagged Memory Deficits: {deficit_count} capacity hazards")
    print(f"    └── Output Target: '{out_file}'")

if __name__ == "__main__":
    generate_cyclonedx_cbom()
