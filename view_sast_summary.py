import json
from collections import Counter

with open("production_sast_cbom_evidence.json") as f:
    data = json.load(f)

print(f"==================================================")
print(f" TOTAL EXTRACTED CRYPTOGRAPHIC DECLARATIONS: {len(data)}")
print(f"==================================================\n")

# 1. Distribution by AST Type
type_counts = Counter(d.get("ast_type", "Unknown") for d in data)
print("[-] Breakdown by AST Node Type:")
for ast_type, count in type_counts.most_common():
    print(f"    • {ast_type:<30} : {count:>5}")

# 2. Java Cryptographic Algorithms (JCA Calls)
jca_algos = Counter(d.get("algorithm_call") for d in data if "algorithm_call" in d)
print(f"\n[-] Top Java JCA Algorithm Transformations (jPOS Switch):")
for algo, count in jca_algos.most_common(10):
    print(f"    • {algo:<30} : {count:>5} calls")

# 3. PKCS#11 Mechanisms & Constants (SoftHSM2 Token)
pkcs_mechs = Counter(d.get("pkcs11_constant") for d in data if "pkcs11_constant" in d and d.get("pkcs11_constant").startswith("CKM_"))
print(f"\n[-] Top PKCS#11 Mechanism Constants (SoftHSM2 HSM Backend):")
for mech, count in pkcs_mechs.most_common(10):
    print(f"    • {mech:<30} : {count:>5} occurrences")

# 4. Critical Buffer Sizing Allocations
buf_sizes = Counter(d.get("allocated_bytes") for d in data if "allocated_bytes" in d)
print(f"\n[-] Top Buffer Sizing Allocations (Bytes):")
for size, count in sorted(buf_sizes.items(), key=lambda x: x[1], reverse=True)[:10]:
    bits = size * 8
    print(f"    • {size:>5} bytes ({bits:>5} bits)           : {count:>5} buffers")

print("\n==================================================")
