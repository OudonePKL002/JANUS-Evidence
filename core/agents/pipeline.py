"""Multi-Agent Orchestration Pipeline for JANUS-Evidence.

Implements Section 1.2 (Objective 3) and Section 2 of the JANUS-Evidence
Master Project Plan (v1.2.0):
    Auditor -> Localization -> RCA -> EvidenceGate (Max R=3) -> Exploit
If any RCA claim remains ungrounded after R=3 revision rounds, the pipeline
abstains with `INCONCLUSIVE` and halts prior to exploit synthesis.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.agents.auditor_agent import AuditorAgent
from core.agents.base_agent import AgentOutput
from core.agents.exploit_agent import ExploitAgent
from core.agents.localization_agent import LocalizationAgent
from core.agents.rca_agent import RCAAgent
from core.analyzer.graph_builder import EvidenceGraph
from core.gate.evidence_gate import (
    DEFAULT_MAX_REVISION_ROUNDS,
    CausalClaim,
    EvidenceGate,
    GateDecision,
    GateVerdict,
)


class PipelineResult(BaseModel):
    """Structured end-to-end execution result of the 4-agent `JanusPipeline`."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    incident_id: Optional[str] = Field(default=None, description="Target incident identifier")
    status: str = Field(
        ...,
        description="Terminal pipeline status: VERIFIED_FOR_EXPLOIT or INCONCLUSIVE",
    )
    gate_verdict: GateVerdict = Field(
        ...,
        description="Detailed Evidence Gate verdict including rounds_used and claim states",
    )
    auditor_output: AgentOutput = Field(..., description="Stage 1: Auditor hypotheses H")
    localization_output: AgentOutput = Field(
        ..., description="Stage 2: Localization Top-k candidates L"
    )
    rca_output: AgentOutput = Field(..., description="Stage 3: 6-Slot Causal Chain output")
    exploit_output: Optional[AgentOutput] = Field(
        default=None,
        description="Stage 4: Exploit replay plan (None if gate abstained with INCONCLUSIVE)",
    )
    verified_claims: List[CausalClaim] = Field(
        default_factory=list,
        description="Final verified 6-slot causal claims (empty if INCONCLUSIVE)",
    )

    @property
    def is_verified(self) -> bool:
        """Return True iff the pipeline passed the Evidence Gate and ran the ExploitAgent."""
        return self.status == GateDecision.VERIFIED_FOR_EXPLOIT.value


class JanusPipeline:
    """Orchestrates the 4 role-specialized agents with the Evidence Gate (R=3 revision loop)."""

    def __init__(
        self,
        auditor_agent: Optional[AuditorAgent] = None,
        localization_agent: Optional[LocalizationAgent] = None,
        rca_agent: Optional[RCAAgent] = None,
        exploit_agent: Optional[ExploitAgent] = None,
        max_revision_rounds: int = DEFAULT_MAX_REVISION_ROUNDS,
    ) -> None:
        if max_revision_rounds < 1:
            raise ValueError(f"max_revision_rounds must be >= 1, got {max_revision_rounds}.")

        self.auditor_agent: AuditorAgent = auditor_agent or AuditorAgent()
        self.localization_agent: LocalizationAgent = localization_agent or LocalizationAgent()
        self.rca_agent: RCAAgent = rca_agent or RCAAgent()
        self.exploit_agent: ExploitAgent = exploit_agent or ExploitAgent()
        self.max_revision_rounds: int = max_revision_rounds

    def run(
        self,
        evidence_graph: EvidenceGraph,
        initial_context: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """Execute the full 4-agent pipeline over `evidence_graph`.

        Sequence:
          1. `AuditorAgent.execute(...)` -> Hypotheses H
          2. `LocalizationAgent.execute(...)` -> Top-k Locations L
          3. `RCAAgent.execute(...)` -> 6-Slot Causal Chain
          4. `EvidenceGate.evaluate_causal_chain(..., max_rounds=R)` with `RCAAgent.revise` hook
          5. If `VERIFIED_FOR_EXPLOIT`, run `ExploitAgent.execute(...)`;
             if `INCONCLUSIVE`, abstain and halt.
        """
        context: Dict[str, Any] = dict(initial_context or {})

        # Stage 1: Auditor Agent -> Hypotheses H
        auditor_out = self.auditor_agent.execute(context, evidence_graph)
        context["auditor"] = auditor_out.payload

        # Stage 2: Localization Agent -> Top-k Locations L
        localization_out = self.localization_agent.execute(context, evidence_graph)
        context["localization"] = localization_out.payload

        # Stage 3: RCA Agent -> Initial 6-Slot Causal Chain
        rca_out = self.rca_agent.execute(context, evidence_graph)
        context["rca"] = rca_out.payload

        # Stage 4: Evidence Gate with R=3 Iterative Revision Hook connected to RCAAgent.revise
        gate = EvidenceGate(
            evidence_graph=evidence_graph,
            default_max_rounds=self.max_revision_rounds,
        )

        def _revision_hook(current_claims: List[CausalClaim], round_idx: int) -> List[CausalClaim]:
            return self.rca_agent.revise(
                claims=current_claims,
                round_idx=round_idx,
                evidence_graph=evidence_graph,
            )

        gate_verdict = gate.evaluate_causal_chain(
            claims=rca_out.claims,
            max_rounds=self.max_revision_rounds,
            revision_callback=_revision_hook,
        )

        # Update RCA output claims to reflect post-gate statuses
        rca_out.claims = gate_verdict.claims

        # Halt & abstain if Evidence Gate returned INCONCLUSIVE after R=3 rounds
        if not gate_verdict.is_verified:
            return PipelineResult(
                incident_id=evidence_graph.incident_id,
                status=GateDecision.INCONCLUSIVE.value,
                gate_verdict=gate_verdict,
                auditor_output=auditor_out,
                localization_output=localization_out,
                rca_output=rca_out,
                exploit_output=None,
                verified_claims=[],
            )

        # Stage 5: Exploit Agent -> Historical Fork Replay Plan
        context["verified_claims"] = [c.model_dump(mode="json") for c in gate_verdict.claims]
        exploit_out = self.exploit_agent.execute(context, evidence_graph)

        return PipelineResult(
            incident_id=evidence_graph.incident_id,
            status=GateDecision.VERIFIED_FOR_EXPLOIT.value,
            gate_verdict=gate_verdict,
            auditor_output=auditor_out,
            localization_output=localization_out,
            rca_output=rca_out,
            exploit_output=exploit_out,
            verified_claims=gate_verdict.claims,
        )

