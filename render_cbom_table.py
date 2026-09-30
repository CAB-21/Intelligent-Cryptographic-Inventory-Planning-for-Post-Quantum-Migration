"""
render_cbom_table.py: Translates CycloneDX v1.6 CBOM JSON into 
structured, human-readable tabular formats (Terminal Tables & CSV).
"""

import json
import csv
import os

def main():
    cbom_file = "cyclonedx_v1.6_cbom.json"
    if not os.path.exists(cbom_file):
        print(f"[!] File '{cbom_file}' not found.")
        return

    with open(cbom_file, "r") as f:
        cbom = json.load(f)

    components = cbom.get("components", [])
    dependencies = cbom.get("dependencies", [])

    # Map bom-ref to component name
    ref_to_name = {c.get("bom-ref"): c.get("name", "Unknown") for c in components}

    # 1. Process Cryptographic Assets
    crypto_rows = []
    for c in components:
        if c.get("type") == "cryptographic-asset":
            props = {p.get("name"): p.get("value") for p in c.get("properties", [])}
            crypto_props = c.get("cryptoProperties", {}).get("algorithmProperties", {})
            
            crypto_rows.append({
                "Asset Name": str(c.get("name", "N/A")),
                "Type": str(crypto_props.get("primitive", "N/A")),
                "Environment": str(crypto_props.get("executionEnvironment", "N/A")),
                "Urgency": str(props.get("pqc:quantum_urgency_score", "0.0")),
                "PQC Replacement": str(props.get("pqc:replacement_target", "N/A")),
                "Provenance": str(props.get("pqc:epistemic_provenance", "N/A"))
            })

    # 2. Process Buffer Deficit Hazards
    deficit_rows = []
    for dep in dependencies:
        props = {p.get("name"): p.get("value") for p in dep.get("properties", [])}
        if props.get("pqc:hazard_type") == "BUFFER_CAPACITY_DEFICIT":
            src = ref_to_name.get(dep.get("ref"), str(dep.get("ref", "Unknown")))
            targets = [ref_to_name.get(d, str(d)) for d in dep.get("dependsOn", [])]
            target_str = ", ".join(targets) if targets else "N/A"
            deficit_val = props.get("pqc:margin_deficit_bytes", "0")

            try:
                numeric_def = int(deficit_val)
                hazard_level = "CRITICAL" if numeric_def < -100 else "HIGH"
            except ValueError:
                hazard_level = "HIGH"

            deficit_rows.append({
                "Buffer Allocation Site": src,
                "Target Primitive": target_str,
                "Margin Deficit": f"{deficit_val} B",
                "Risk": hazard_level
            })

    # =========================================================================
    # DISPLAY TABLE 1: INVENTORIED CRYPTOGRAPHIC ASSETS
    # =========================================================================
    print("\n" + "="*115)
    print(f"  TABLE 1: AUDITED CRYPTOGRAPHIC ASSETS (CYCLONEDX v1.6 INVENTORY) - TOTAL: {len(crypto_rows)}")
    print("="*115)
    print(f"{'Asset Name':<28} | {'Type':<14} | {'Environment':<22} | {'Urgency':<8} | {'PQC Replacement':<18} | {'Provenance':<16}")
    print("-"*115)
    for r in crypto_rows[:15]:
        print(f"{r['Asset Name'][:28]:<28} | {r['Type'][:14]:<14} | {r['Environment'][:22]:<22} | {r['Urgency']:<8} | {r['PQC Replacement'][:18]:<18} | {r['Provenance'][:16]:<16}")
    if len(crypto_rows) > 15:
        print(f"... and {len(crypto_rows) - 15} more cryptographic assets.")
    print("="*115)

    # =========================================================================
    # DISPLAY TABLE 2: BUFFER CAPACITY DEFICIT HAZARDS
    # =========================================================================
    print("\n" + "="*115)
    print(f"  TABLE 2: PHYSICAL MEMORY CAPACITY DEFICITS (PQC OVERFLOW HAZARDS) - TOTAL: {len(deficit_rows)}")
    print("="*115)
    print(f"{'Buffer Allocation Site':<48} | {'Target Primitive':<24} | {'Margin Deficit':<16} | {'Risk':<10}")
    print("-"*115)
    for r in deficit_rows[:15]:
        buf_site = r.get("Buffer Allocation Site", "N/A")[:48]
        target_prim = r.get("Target Primitive", "N/A")[:24]
        margin_def = r.get("Margin Deficit", "N/A")[:16]
        risk_lvl = r.get("Risk", "N/A")[:10]
        print(f"{buf_site:<48} | {target_prim:<24} | {margin_def:<16} | {risk_lvl:<10}")
    if len(deficit_rows) > 15:
        print(f"... and {len(deficit_rows) - 15} more buffer deficit hazards.")
    print("="*115)

    # Export to CSV
    csv_crypto = "cbom_crypto_assets_table.csv"
    with open(csv_crypto, "w", newline="") as f:
        if crypto_rows:
            writer = csv.DictWriter(f, fieldnames=list(crypto_rows[0].keys()))
            writer.writeheader()
            writer.writerows(crypto_rows)

    csv_deficits = "cbom_memory_deficits_table.csv"
    with open(csv_deficits, "w", newline="") as f:
        if deficit_rows:
            writer = csv.DictWriter(f, fieldnames=list(deficit_rows[0].keys()))
            writer.writeheader()
            writer.writerows(deficit_rows)

    print(f"\n[+] Tabular CSV exports generated successfully:")
    print(f"    ├── {csv_crypto} ({len(crypto_rows)} rows)")
    print(f"    └── {csv_deficits} ({len(deficit_rows)} rows)")

if __name__ == "__main__":
    main()
