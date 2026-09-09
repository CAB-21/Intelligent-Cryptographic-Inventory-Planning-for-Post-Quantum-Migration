"""
cbom_ontology.py: Canonical Cryptographic Ontology & Epistemic Provenance
Strict separation of primitive classes, NIST migration strategies, and evidence tiers.
"""

from enum import Enum
from typing import Dict, List, Optional, Any

# ============================================================================
# 1. ENTITY & PRIMITIVE CLASSIFICATION
# ============================================================================

class NodeClass(Enum):
    SOURCE_NODE = "SourceNode"                 # Code scope (Java class / C++ file)
    CRYPTO_PRIMITIVE = "CryptoPrimitiveNode"   # Distinct cryptographic algorithm/mechanism
    KEY_ASSET = "KeyAssetNode"                 # Handle, keystore, or private key
    BUFFER_NODE = "BufferNode"                 # Memory allocation
    RUNTIME_EVENT = "RuntimeEventNode"         # Distinct eBPF kernel trace
    NETWORK_ENDPOINT = "NetworkEndpointNode"   # Live socket pair
    PQC_TARGET = "PQCTargetNode"               # NIST FIPS standard replacement


class PrimitiveCategory(Enum):
    ASYMMETRIC_SIGNATURE = "Digital Signature"
    KEY_ENCAPSULATION = "Key Encapsulation Mechanism (KEM)"
    SYMMETRIC_CIPHER = "Symmetric Encryption"
    MAC = "Message Authentication Code"
    HASH_DIGEST = "Cryptographic Hash Function"
    KEY_AGREEMENT = "Key Agreement (DH/ECDH)"


class ProvenanceTier(Enum):
    TIER_1_DYNAMIC_OBSERVED = "Tier 1: Dynamically Observed (eBPF Kernel Trace)"
    TIER_2_STATIC_ESTABLISHED = "Tier 2: Statically Established (Tree-sitter AST)"
    TIER_3_CROSS_LAYER_FUSED = "Tier 3: Cross-Layer Correlated (AST + DAST + PID)"
    TIER_4_GNN_CANDIDATE = "Tier 4: GNN Unresolved Candidate Link"


class QuantumUrgency(Enum):
    CRITICAL_SHOR_BROKEN = 1.0   # RSA, ECDSA, DSA, ECDH
    HIGH_LEGACY_BROKEN = 0.8     # MD5, SHA-1, DES, 3DES
    MEDIUM_GROVER_REDUCE = 0.3   # AES-128
    QUANTUM_RESISTANT = 0.0      # AES-256, SHA-384, SHA-512, NIST PQC


# ============================================================================
# 2. CANONICAL REPLACEMENT STRATEGIES (NIST FIPS COMPLIANT)
# ============================================================================

CANONICAL_MIGRATION_STRATEGIES = {
    # Signatures (RSA/ECDSA -> ML-DSA-65 NIST FIPS 204)
    "RSA_SIGNATURE": {
        "target": "ML-DSA-65",
        "standard": "NIST FIPS 204",
        "category": PrimitiveCategory.ASYMMETRIC_SIGNATURE.value,
        "type": "Stateless Lattice Digital Signature",
        "required_output_bytes": 3309
    },
    "ECDSA_SIGNATURE": {
        "target": "ML-DSA-65",
        "standard": "NIST FIPS 204",
        "category": PrimitiveCategory.ASYMMETRIC_SIGNATURE.value,
        "type": "Stateless Lattice Digital Signature",
        "required_output_bytes": 3309
    },
    # Key Agreement / KEM (DH/ECDH -> ML-KEM-768 NIST FIPS 203)
    "KEY_EXCHANGE": {
        "target": "ML-KEM-768",
        "standard": "NIST FIPS 203",
        "category": PrimitiveCategory.KEY_ENCAPSULATION.value,
        "type": "Lattice Key Encapsulation Mechanism",
        "required_output_bytes": 1088
    },
    # Symmetric 3DES -> AES-256-GCM (Symmetric Replacement)
    "3DES_ENCRYPTION": {
        "target": "AES-256-GCM",
        "standard": "NIST SP 800-38D",
        "category": PrimitiveCategory.SYMMETRIC_CIPHER.value,
        "type": "Authenticated Symmetric Block Cipher",
        "required_output_bytes": 64
    },
    # Legacy SHA-1 MAC -> KMAC-256 (NIST SP 800-185)
    "SHA1_MAC": {
        "target": "KMAC-256",
        "standard": "NIST SP 800-185",
        "category": PrimitiveCategory.MAC.value,
        "type": "Quantum-Resistant Message Authentication Code",
        "required_output_bytes": 64
    },
    # Legacy MD5 / SHA-1 Hash -> SHA-384 / SHA-512 (FIPS 180-4)
    "LEGACY_HASH": {
        "target": "SHA-384",
        "standard": "NIST FIPS 180-4",
        "category": PrimitiveCategory.HASH_DIGEST.value,
        "type": "Cryptographic Hash Function",
        "required_output_bytes": 48
    }
}
