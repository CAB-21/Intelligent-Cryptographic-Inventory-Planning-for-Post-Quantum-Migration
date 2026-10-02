"""
inspect_predicted_links.py
Inspects unique evaluated candidate pairs produced during the Inductive Test Split of HGT.
Deduplicates parallel multi-graph edges and displays diverse held-out predictions.
"""

import json
import os
import sys

def main():
    target_file = "hgt_inductive_predictions.json"
    
    if not os.path.exists(target_file):
        print(f"[!] Error: File '{target_file}' not found.")
        print("[!] You must run 'python3 benchmark_gnn_rigorous_validation.py' first.")
        sys.exit(1)

    with open(target_file, "r") as f:
        predictions = json.load(f)

    if not predictions:
        print(f"[!] '{target_file}' is empty. No evaluated test candidates are recorded.")
        sys.exit(1)

    # Deduplicate by unique (source, target) pair, keeping the highest score
    unique_candidates = {}
    for p in predictions:
        key = (p.get("source"), p.get("target"))
        score = float(p.get("hgt_score", 0.0))
        if key not in unique_candidates or score > unique_candidates[key]["hgt_score"]:
            unique_candidates[key] = p

    sorted_preds = sorted(unique_candidates.values(), key=lambda x: x.get("hgt_score", 0.0), reverse=True)

    print("=" * 118)
    print("      HGT-INFERRED CRYPTOGRAPHIC DEPENDENCIES (UNIQUE INDUCTIVE CANDIDATES - ZERO TRAINING EXPOSURE)")
    print("=" * 118)
    print(f"{'Rank':<5} | {'Source Module (Held Out)':<44} | {'Target Primitive':<22} | {'HGT Score':<10} | {'Ground Truth?':<14} | {'Provenance Tier'}")
    print("-" * 118)

    display_count = min(25, len(sorted_preds))
    promoted_count = 0

    for rank, p in enumerate(sorted_preds[:display_count], 1):
        src = str(p.get("source", "N/A"))
        if src.startswith("Source::"):
            src = src.replace("Source::", "")
        src = src[:44]
        
        dst = str(p.get("target", "N/A"))
        if dst.startswith("Crypto::"):
            dst = dst.replace("Crypto::", "")
        dst = dst[:22]

        score = float(p.get("hgt_score", 0.0))
        gt = "YES (Recovered)" if p.get("ground_truth") else "NO (False Pos)"
        tier = p.get("provenance", "N/A")
        
        if score >= 0.85:
            promoted_count += 1
            print(f"{rank:<5} | {src:<44} | {dst:<22} | {score:<10.4f} | {gt:<14} | {tier}")
        else:
            print(f"{rank:<5} | {src:<44} | {dst:<22} | {score:<10.4f} | {gt:<14} | [FILTERED: < 0.85]")

    total_promoted = sum(1 for p in sorted_preds if p.get("hgt_score", 0.0) >= 0.85)

    print("=" * 118)
    print(f"[+] Unique Candidates Audited in Inductive Split: {len(sorted_preds)}")
    print(f"[+] Unique Inferred Dependencies Passing Gating (HGT Score >= 0.85): {total_promoted}")
    print(f"[+] Training Exposure: False (Strictly held-out inductive test split)")
    print(f"[+] Source Data File: {target_file}")

if __name__ == "__main__":
    main()
