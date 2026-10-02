"""
inspect_predicted_links.py
Audits model link prediction dynamics on the Cold-Start Inductive test split.
Handles tied scores deterministically and separates ranking dynamics from gating.
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
        print(f"[!] '{target_file}' is empty.")
        sys.exit(1)

    # Sort deterministically: score DESC, ground_truth ASC (conservative on ties), source ASC
    sorted_preds = sorted(
        predictions, 
        key=lambda x: (x.get("hgt_score", 0.0), -int(x.get("ground_truth", False)), x.get("source", "")), 
        reverse=True
    )
    
    total_candidates = len(sorted_preds)
    total_positives = sum(1 for p in sorted_preds if p.get("ground_truth", False))
    total_negatives = total_candidates - total_positives

    print("=" * 118)
    print("      HGT COLD-START INDUCTIVE PREDICTIONS (RANK-ORDERED BY MODEL CONFIDENCE)")
    print("=" * 118)
    print(f"{'Rank':<5} | {'Source Module (Held Out)':<42} | {'Target Primitive':<22} | {'Score':<8} | {'Ground Truth?':<16} | {'Status'}")
    print("-" * 118)

    top_display = min(20, total_candidates)
    top_10_hits = sum(1 for p in sorted_preds[:10] if p.get("ground_truth", False))
    top_20_hits = sum(1 for p in sorted_preds[:20] if p.get("ground_truth", False))

    for rank, p in enumerate(sorted_preds[:top_display], 1):
        src = str(p.get("source", "N/A")).replace("Source::", "")[:42]
        dst = str(p.get("target", "N/A")).replace("Crypto::", "")[:22]
        score = float(p.get("hgt_score", 0.0))
        gt = p.get("ground_truth", False)
        gt_str = "YES (Recovered)" if gt else "NO (False Pos)"
        status = "TIER_4_CANDIDATE" if score >= 0.85 else f"[Ranked #{rank}]"
        
        print(f"{rank:<5} | {src:<42} | {dst:<22} | {score:<8.4f} | {gt_str:<16} | {status}")

    # Operational Promotion Audit (Score >= 0.85)
    promoted = [p for p in sorted_preds if p.get("hgt_score", 0.0) >= 0.85]
    promoted_true = sum(1 for p in promoted if p.get("ground_truth", False))

    print("=" * 118)
    print("  AUDIT METRICS & STATISTICAL BREAKDOWN")
    print("=" * 118)
    print(f"[+] Total Test Candidates: {total_candidates} ({total_positives} Ground-Truth Positives, {total_negatives} Negatives)")
    print(f"[+] Top-10 Conservative Ranking Precision: {top_10_hits}/10 ({float(top_10_hits)/10 * 100:.1f}%)")
    print(f"[+] Top-20 Conservative Ranking Precision: {top_20_hits}/20 ({float(top_20_hits)/20 * 100:.1f}%)")
    print(f"[+] Peak Inferred Link Score: {sorted_preds[0]['hgt_score']:.4f} (Rank #1: {sorted_preds[0]['source']} -> {sorted_preds[0]['target']})")
    print(f"[+] Operational Gating Status (Threshold >= 0.85):")
    print(f"    - Candidates Promoted to Tier-4: {len(promoted)}")
    if len(promoted) > 0:
        print(f"    - Promotion Precision: {float(promoted_true)/len(promoted)*100:.1f}% ({promoted_true}/{len(promoted)})")
    else:
        print(f"    - Note: In strict cold-start settings, raw uncalibrated sigmoid scores compress toward the prior.")
        print(f"      Candidates require validation-split calibration or percentile ranking before Tier-4 promotion.")
    print("=" * 118)

if __name__ == "__main__":
    main()
