"""
cbom_ontology.py: Formal Heterogeneous Cryptographic Dependency Ontology
Defines entity classes, edge relations, provenance tiers, and quantum risk scoring.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

# ============================================================================
# 1. ENTITY CLASSIFICATION (NODE TYPES)
# ============================================================================

class NodeClass(Enum):
    SOURCE_NODE = "SourceNode"                 # Java / C++ Code Scope
    CRYPTO_NODE = "CryptoNode"                 # Cipher, Mechanism, Digest Primitive
    CERT_KEY_NODE = "CertKeyNode"             # Key Handles, Keystores, Certificates
    BUFFER_NODE = "BufferNode"                 # Memory Buffers & Allocations
    RUNTIME_NODE = "RuntimeNode"               # Kernel eBPF Telemetry Events
    NETWORK_ENDPOINT_NODE = "NetworkEndpoint"  # Socket Pairs & Protocol Channels
    PQC_TARGET_NODE = "PQCTargetNode"          # NIST FIPS 203/204/205 Standards


class ProvenanceTier(Enum):
    TIER_1_DYNAMIC_OBSERVED = "Level 1: Dynamically Observed (eBPF Kernel Trap)"
    TIER_2_STATIC_ESTABLISHED = "Level 2: Statically Established (Tree-sitter AST)"
    TIER_3_CROSS_LAYER_FUSED = "Level 3: Cross-Layer Correlated (AST + PID + Socket)"
    TIER_4_GNN_INFERRED = "Level 4: GNN Inferred (Probabilistic Link)"


class QuantumUrgency(Enum):
    CRITICAL_VULNERABLE = 1.0   # Shor's algorithm broken (RSA, ECDSA, ECDH)
    HIGH_LEGACY_VULN = 0.8      # Broken classical (DES, 3DES, MD5, SHA-1)
    MEDIUM_GROVER_RISK = 0.3    # Grover's algorithm impact (AES-128)
    QUANTUM_RESISTANT = 0.0     # AES-256, SHA-384, SHA-512, NIST PQC


# ============================================================================
# 2. EVIDENCE DATA STRUCTURES
# ============================================================================

@dataclass
class MultiModalEvidence:
    ast_provenance: Optional[str] = None
    ebpf_uprobe: Optional[str] = None
    pid: Optional[int] = None
    binary_path: Optional[str] = None
    socket_endpoint: Optional[str] = None
    confidence_tier: ProvenanceTier = ProvenanceTier.TIER_2_STATIC_ESTABLISHED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ast_provenance": self.ast_provenance,
            "ebpf_uprobe": self.ebpf_uprobe,
            "pid": self.pid,
            "binary_path": self.binary_path,
            "socket_endpoint": self.socket_endpoint,
            "confidence_tier": self.confidence_tier.value
        }


# ============================================================================
# 3. NIST PQC REPLACEMENT SPECIFICATIONS (GROUND TRUTH)
# ============================================================================

NIST_PQC_CATALOG = {
    "ML-DSA-65": {
        "standard": "NIST FIPS 204",
        "category": "Stateful/Lattice Digital Signature",
        "public_key_bytes": 1952,
        "signature_bytes": 3309,
        "security_category": 3,
        "replaces": ["RSA-2048", "RSA-4096", "ECDSA-P256", "CKM_RSA_PKCS"]
    },
    "ML-KEM-768": {
        "standard": "NIST FIPS 203",
        "category": "Lattice Key Encapsulation (KEM)",
        "public_key_bytes": 1184,
        "ciphertext_bytes": 1088,
        "security_category": 3,
        "replaces": ["ECDH", "DH-2048", "RSA-OAEP", "CKM_RSA_PKCS_KEY_PAIR_GEN"]
    },
    "SLH-DSA-128s": {
        "standard": "NIST FIPS 205",
        "category": "Stateless Hash-Based Digital Signature",
        "public_key_bytes": 32,
        "signature_bytes": 7856,
        "security_category": 1,
        "replaces": ["Fallback_Signatures"]
    }
}
