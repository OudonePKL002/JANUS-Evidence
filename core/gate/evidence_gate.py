"""Formal Evidence Gate and Iterative Revision Loop (R=3) Implementation.

Implements Section 1.2 (Objective 1) and Section 2 of the JANUS-Evidence Master
Project Plan (v1.2.0). Every agent claim must link directly to structural or
on-chain execution evidence in G = (N, E). Claims with missing or hallucinated
pointers are marked UNGROUNDED for revision (up to R=3 rounds); if unresolved,
the gate abstains and returns INCONCLUSIVE.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable, ClassVar, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.analyzer.graph_builder import EvidenceGraph

DEFAULT_MAX_REVISION_ROUNDS: int = 3

VALID_AGENT_ROLES = frozenset({"Auditor", "Localization", "Localizer", "RCA", "Exploit"})


class ClaimStatus(str, Enum):
    """Lifecycle status of a CausalClaim evaluated by the Evidence Gate."""

    PENDING = "PENDING"
    GROUNDED = "GROUNDED"
    UNGROUNDED = "UNGROUNDED"
    INCONCLUSIVE = "INCONCLUSIVE"


class GateDecision(str, Enum):
    """Terminal verdicts emitted by the Evidence Gate after evaluating a causal chain."""

    VERIFIED_FOR_EXPLOIT = "VERIFIED_FOR_EXPLOIT"
    INCONCLUSIVE = "INCONCLUSIVE"


class CausalClaim(BaseModel):
    """Pointer-backed causal statement emitted by a JANUS agent."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    claim_id: str = Field(..., min_length=1, description="Unique identifier for the causal claim")
    agent_role: str = Field(
        ...,
        min_length=1,
        description="Originating agent role (Auditor, Localization, RCA, Exploit)",
    )
    statement: str = Field(
        ...,
        min_length=1,
        description="Natural-language or formal causal claim description",
    )
    evidence_pointers: List[str] = Field(
        default_factory=list,
        description="Target node IDs, statement IDs, or canonical edge pointers in G=(N,E)",
    )
    status: ClaimStatus = Field(
        default=ClaimStatus.PENDING,
        description="Current grounding verification status",
    )
    invalid_pointers: List[str] = Field(
        default_factory=list,
        description="Pointers that failed EvidenceGraph.has_pointer() lookup",
    )
    revision_round: int = Field(
        default=0,
        ge=0,
        description="Revision iteration index in which this claim was last evaluated",
    )

    @field_validator("agent_role")
    @classmethod
    def validate_agent_role(cls, value: str) -> str:
        if value not in VALID_AGENT_ROLES:
            raise ValueError(
                f"Invalid agent_role '{value}'. Expected one of {sorted(VALID_AGENT_ROLES)}."
            )
        return value


class GateVerdict(BaseModel):
    """Structured outcome of evaluating a causal chain through the Evidence Gate (max R=3)."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    VERIFIED_FOR_EXPLOIT: ClassVar[str] = GateDecision.VERIFIED_FOR_EXPLOIT.value
    INCONCLUSIVE: ClassVar[str] = GateDecision.INCONCLUSIVE.value

    verdict: GateDecision = Field(..., description="Terminal gate verdict")
    rounds_used: int = Field(..., ge=0, description="Number of verification/revision rounds executed")
    max_rounds: int = Field(
        default=DEFAULT_MAX_REVISION_ROUNDS,
        ge=1,
        description="Maximum allowed revision rounds (R=3)",
    )
    claims: List[CausalClaim] = Field(
        default_factory=list,
        description="Final state of all evaluated claims",
    )
    ungrounded_claim_ids: List[str] = Field(
        default_factory=list,
        description="IDs of claims that remained ungrounded/inconclusive",
    )
    feedback: List[str] = Field(
        default_factory=list,
        description="Diagnostic messages detailing failed pointers across rounds",
    )

    @property
    def status(self) -> str:
        """Return the string representation of the gate verdict."""
        return self.verdict.value

    @property
    def is_verified(self) -> bool:
        """Return True iff the causal chain passed pointer validation."""
        return self.verdict == GateDecision.VERIFIED_FOR_EXPLOIT

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GateDecision):
            return self.verdict == other
        if isinstance(other, str):
            return self.verdict.value == other
        return super().__eq__(other)


RevisionCallback = Callable[[List[CausalClaim], int], List[CausalClaim]]


class EvidenceGate:
    """Formal Evidence Gate verifying causal claims against an EvidenceGraph G = (N, E).

    Enforces pointer grounding and manages the iterative revision loop (max_rounds = 3).
    """

    def __init__(
        self,
        evidence_graph: EvidenceGraph,
        default_max_rounds: int = DEFAULT_MAX_REVISION_ROUNDS,
    ) -> None:
        if not isinstance(evidence_graph, EvidenceGraph):
            raise TypeError(
                f"Expected an EvidenceGraph instance, got {type(evidence_graph).__name__}."
            )
        if default_max_rounds < 1:
            raise ValueError("default_max_rounds must be >= 1.")
        self.evidence_graph: EvidenceGraph = evidence_graph
        self.default_max_rounds: int = default_max_rounds

    def verify_claim(self, claim: CausalClaim) -> CausalClaim:
        """Verify all pointers in `claim.evidence_pointers` against `self.evidence_graph`.

        - If `evidence_pointers` is non-empty and all pointers exist in G, marks `GROUNDED`.
        - If `evidence_pointers` is empty or any pointer fails lookup, marks `UNGROUNDED`.
        """
        if not isinstance(claim, CausalClaim):
            raise TypeError(f"Expected a CausalClaim instance, got {type(claim).__name__}.")

        if not claim.evidence_pointers:
            claim.invalid_pointers = []
            claim.status = ClaimStatus.UNGROUNDED
            return claim

        missing: List[str] = [
            ptr for ptr in claim.evidence_pointers if not self.evidence_graph.has_pointer(ptr)
        ]
        claim.invalid_pointers = missing

        if not missing:
            claim.status = ClaimStatus.GROUNDED
        else:
            claim.status = ClaimStatus.UNGROUNDED

        return claim

    def evaluate_causal_chain(
        self,
        claims: List[CausalClaim],
        max_rounds: int = DEFAULT_MAX_REVISION_ROUNDS,
        revision_callback: Optional[RevisionCallback] = None,
    ) -> GateVerdict:
        """Evaluate a list of causal claims with an iterative revision loop (default R=3).

        Args:
            claims: The sequence of causal claims (e.g., 6-slot RCA chain) to verify.
            max_rounds: Maximum verification/revision attempts before abstaining (default R=3).
            revision_callback: Optional callback `(current_claims, round_idx) -> revised_claims`
                invoked when `UNGROUNDED` claims are detected and rounds remain.

        Returns:
            `GateVerdict` with `VERIFIED_FOR_EXPLOIT` if all claims are grounded within
            `max_rounds`, or `INCONCLUSIVE` if any claim remains ungrounded after `max_rounds`.
        """
        if max_rounds < 1:
            raise ValueError(f"max_rounds must be >= 1, got {max_rounds}.")

        if not claims:
            return GateVerdict(
                verdict=GateDecision.INCONCLUSIVE,
                rounds_used=0,
                max_rounds=max_rounds,
                claims=[],
                ungrounded_claim_ids=[],
                feedback=["Empty causal claim chain cannot be verified; abstaining as INCONCLUSIVE."],
            )

        current_claims: List[CausalClaim] = [c.model_copy(deep=True) for c in claims]
        feedback_log: List[str] = []
        rounds_executed = 0

        for round_idx in range(1, max_rounds + 1):
            rounds_executed = round_idx
            ungrounded_in_round: List[CausalClaim] = []

            for claim in current_claims:
                claim.revision_round = round_idx
                self.verify_claim(claim)
                if claim.status != ClaimStatus.GROUNDED:
                    ungrounded_in_round.append(claim)
                    if not claim.evidence_pointers:
                        feedback_log.append(
                            f"[Round {round_idx}] Claim '{claim.claim_id}' ({claim.agent_role}) "
                            "is UNGROUNDED: empty evidence_pointers."
                        )
                    else:
                        feedback_log.append(
                            f"[Round {round_idx}] Claim '{claim.claim_id}' ({claim.agent_role}) "
                            f"is UNGROUNDED: invalid pointers {claim.invalid_pointers}."
                        )

            # All claims grounded -> advance to Exploit Agent
            if not ungrounded_in_round:
                return GateVerdict(
                    verdict=GateDecision.VERIFIED_FOR_EXPLOIT,
                    rounds_used=rounds_executed,
                    max_rounds=max_rounds,
                    claims=current_claims,
                    ungrounded_claim_ids=[],
                    feedback=feedback_log,
                )

            # Attempt revision if rounds remain and a revision callback is provided
            if round_idx < max_rounds and revision_callback is not None:
                current_claims = [
                    c.model_copy(deep=True)
                    for c in revision_callback(current_claims, round_idx)
                ]

        # Max rounds R exhausted with ungrounded claims remaining -> abstain (INCONCLUSIVE)
        ungrounded_ids: List[str] = []
        for claim in current_claims:
            if claim.status != ClaimStatus.GROUNDED:
                claim.status = ClaimStatus.INCONCLUSIVE
                ungrounded_ids.append(claim.claim_id)

        feedback_log.append(
            f"[Terminal] Max revision rounds (R={max_rounds}) exhausted. "
            f"Abstaining with INCONCLUSIVE for claims: {ungrounded_ids}."
        )

        return GateVerdict(
            verdict=GateDecision.INCONCLUSIVE,
            rounds_used=rounds_executed,
            max_rounds=max_rounds,
            claims=current_claims,
            ungrounded_claim_ids=ungrounded_ids,
            feedback=feedback_log,
        )

