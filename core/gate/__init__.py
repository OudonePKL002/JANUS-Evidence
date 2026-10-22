"""Evidence Gate module for pointer verification and iterative revision loop (R=3)."""

from core.gate.evidence_gate import (
    DEFAULT_MAX_REVISION_ROUNDS,
    CausalClaim,
    ClaimStatus,
    EvidenceGate,
    GateDecision,
    GateVerdict,
)

__all__ = [
    "CausalClaim",
    "ClaimStatus",
    "DEFAULT_MAX_REVISION_ROUNDS",
    "EvidenceGate",
    "GateDecision",
    "GateVerdict",
]
