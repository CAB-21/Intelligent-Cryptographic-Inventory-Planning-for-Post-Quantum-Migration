"""
profile_execution_latency.py: Phase 5 - Ground-Truth Cryptographic Latency Profiler
Processes strictly verified dynamic eBPF timestamps from production telemetry.
"""

import os
import json
import numpy as np

def main():
    print("================================================================================")
    print("  PHASE 5: GROUND-TRUTH CRYPTOGRAPHIC LATENCY PROFILER (eBPF KERNEL TRACE)      ")
    print("================================================================================")

    dast_file = "production_dast_cbom_evidence.json"
    if not os.path.exists(dast_file):
        print(f"[!] DAST file '{dast_file}' not found.")
        return

    with open(dast_file, "r") as f:
        events = json.load(f)

    print(f"[*] Ingested {len(events)} Verified Dynamic Telemetry Records from libsofthsm2.so")

    # Sort events chronologically by nanosecond timestamp
    events.sort(key=lambda x: x["timestamp_ns"])

    # Compute step-to-step transition durations
    transitions = []
    for i in range(len(events) - 1):
        e1 = events[i]
        e2 = events[i + 1]
        delta_ns = e2["timestamp_ns"] - e1["timestamp_ns"]
        delta_us = delta_ns / 1000.0
        delta_ms = delta_us / 1000.0
        transitions.append({
            "from_symbol": e1["symbol"],
            "to_symbol": e2["symbol"],
            "pid": e1["pid"],
            "process": e1["process"],
            "delta_us": round(delta_us, 2),
            "delta_ms": round(delta_ms, 4)
        })

    # Isolate the cryptographic signing pipeline (SignInit -> SignUpdate -> SignFinal)
    sign_init = next((e for e in events if e["symbol"] == "C_SignInit"), None)
    sign_final = next((e for e in events if e["symbol"] == "C_SignFinal"), None)

    pipeline_latency_us = None
    if sign_init and sign_final:
        pipeline_latency_us = (sign_final["timestamp_ns"] - sign_init["timestamp_ns"]) / 1000.0

    print("\n" + "="*95)
    print(f"{'Transition Phase':<35} | {'PID (Process)':<16} | {'Duration (μs)':<15} | {'Duration (ms)':<15}")
    print("="*95)
    for t in transitions:
        phase = f"{t['from_symbol']} -> {t['to_symbol']}"
        print(f"{phase:<35} | {t['pid']} ({t['process']})      | {t['delta_us']:<15.2f} | {t['delta_ms']:<15.4f}")
    print("="*95)

    if pipeline_latency_us:
        print(f"\n[+] Total Verified PKCS#11 Signing Pipeline (SignInit -> SignFinal):")
        print(f"    └── {pipeline_latency_us:,.2f} μs ({pipeline_latency_us / 1000.0:.2f} ms)")

    # Export authentic profile matrix
    out_profile = {
        "telemetry_source": "Linux eBPF Uprobe (libsofthsm2.so)",
        "verified_events_count": len(events),
        "observed_transitions": transitions,
        "signing_pipeline_latency_us": pipeline_latency_us
    }

    out_file = "crypto_execution_latency_profile.json"
    with open(out_file, "w") as f:
        json.dump(out_profile, f, indent=2)

    print(f"\n[+] Authentic execution latency profile saved to '{out_file}'.")

if __name__ == "__main__":
    main()
