"""Base Agent Interface and Shared Output Models for JANUS-Evidence.

Implements the abstract interface for the 4 role-specialized agents
(Auditor -> Localization -> RCA -> Exploit) specified in Section 1.2
(Objective 3) and Section 2 of the JANUS-Evidence Master Project Plan (v1.2.0).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.analyzer.graph_builder import EvidenceGraph
from core.gate.evidence_gate import VALID_AGENT_ROLES, CausalClaim, ClaimStatus

LLMBackendCallable = Callable[[Dict[str, Any], EvidenceGraph], Dict[str, Any]]


class AgentOutput(BaseModel):
    """Standardized output envelope returned by every JANUS-Evidence agent."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    agent_name: str = Field(..., min_length=1, description="Concrete agent instance name")
    agent_role: str = Field(
        ...,
        min_length=1,
        description="Canonical role identifier (Auditor, Localization, RCA, Exploit)",
    )
    claims: List[CausalClaim] = Field(
        default_factory=list,
        description="Pointer-backed causal claims emitted by the agent",
    )
    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Role-specific structured output (e.g., hypotheses H, locations L, 6-slot chain, or exploit plan)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Execution telemetry (e.g., token usage, latency, round counter)",
    )


class BaseAgent(ABC):
    """Abstract base class for all JANUS-Evidence role-specialized security agents."""

    def __init__(
        self,
        name: str,
        role: str,
        llm_backend: Optional[LLMBackendCallable] = None,
    ) -> None:
        if role not in VALID_AGENT_ROLES:
            raise ValueError(
                f"Invalid agent role '{role}'. Must be one of {sorted(VALID_AGENT_ROLES)}."
            )
        self.name: str = name
        self.role: str = role
        self.llm_backend: Optional[LLMBackendCallable] = llm_backend

    @abstractmethod
    def execute(
        self,
        input_data: Dict[str, Any],
        evidence_graph: EvidenceGraph,
    ) -> AgentOutput:
        """Execute the agent's specialized reasoning over `input_data` and `evidence_graph`."""
        raise NotImplementedError

    def build_claim(
        self,
        claim_id: str,
        statement: str,
        evidence_pointers: List[str],
        status: ClaimStatus = ClaimStatus.PENDING,
    ) -> CausalClaim:
        """Construct a standardized `CausalClaim` attributed to `self.role`."""
        return CausalClaim(
            claim_id=claim_id,
            agent_role=self.role,
            statement=statement,
            evidence_pointers=list(evidence_pointers),
            status=status,
        )

