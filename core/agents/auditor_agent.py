"""Auditor Agent for JANUS-Evidence (Stage 1: Hypothesis Generation H).

Generates initial vulnerability hypotheses H (vulnerability class, precondition,
target contract, and preliminary evidence pointers) from the EvidenceGraph G=(N,E).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.agents.base_agent import AgentOutput, BaseAgent, LLMBackendCallable
from core.analyzer.graph_builder import (
    CodeNode,
    EvidenceGraph,
    InvariantNode,
    NodeType,
    StateNode,
    TxNode,
)
from core.gate.evidence_gate import CausalClaim


class VulnerabilityHypothesis(BaseModel):
    """Structured vulnerability hypothesis H emitted by the AuditorAgent."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    hypothesis_id: str = Field(..., min_length=1, description="Unique hypothesis identifier")
    vulnerability_class: str = Field(
        ...,
        min_length=1,
        description="Vulnerability taxonomy class (e.g., REENTRANCY, PRICE_ORACLE_MANIPULATION, ACCESS_CONTROL)",
    )
    precondition: str = Field(
        ...,
        min_length=1,
        description="Protocol or state precondition enabling the vulnerability",
    )
    target_contract: str = Field(
        ...,
        min_length=1,
        description="Primary vulnerable contract name or address",
    )
    evidence_pointers: List[str] = Field(
        default_factory=list,
        description="Pointers into G=(N,E) supporting the initial hypothesis",
    )


class AuditorAgent(BaseAgent):
    """Role-specialized agent that inspects G=(N,E) to emit initial hypotheses H."""

    def __init__(
        self,
        name: str = "JanusAuditorAgent",
        llm_backend: Optional[LLMBackendCallable] = None,
    ) -> None:
        super().__init__(name=name, role="Auditor", llm_backend=llm_backend)

    def execute(
        self,
        input_data: Dict[str, Any],
        evidence_graph: EvidenceGraph,
    ) -> AgentOutput:
        """Generate vulnerability hypotheses H and corresponding pointer-backed claims."""
        if self.llm_backend is not None:
            raw_resp = self.llm_backend(input_data, evidence_graph)
            hypotheses = [
                VulnerabilityHypothesis.model_validate(h)
                for h in raw_resp.get("hypotheses", [])
            ]
        elif "hypotheses" in input_data:
            hypotheses = [
                VulnerabilityHypothesis.model_validate(h)
                for h in input_data["hypotheses"]
            ]
        else:
            hypotheses = self._heuristic_hypotheses(evidence_graph)

        claims: List[CausalClaim] = []
        for hyp in hypotheses:
            claims.append(
                self.build_claim(
                    claim_id=f"CLAIM-AUDITOR-{hyp.hypothesis_id}",
                    statement=(
                        f"[{hyp.vulnerability_class}] Target '{hyp.target_contract}' "
                        f"under precondition: {hyp.precondition}"
                    ),
                    evidence_pointers=hyp.evidence_pointers,
                )
            )

        return AgentOutput(
            agent_name=self.name,
            agent_role=self.role,
            claims=claims,
            payload={
                "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
            },
            metadata={"hypothesis_count": len(hypotheses)},
        )

    def _heuristic_hypotheses(
        self,
        evidence_graph: EvidenceGraph,
    ) -> List[VulnerabilityHypothesis]:
        """Deterministic graph-backed fallback for offline execution and testing."""
        code_nodes = [
            n for n in evidence_graph.get_nodes_by_type(NodeType.CODE) if isinstance(n, CodeNode)
        ]
        state_nodes = [
            n for n in evidence_graph.get_nodes_by_type(NodeType.STATE) if isinstance(n, StateNode)
        ]
        inv_nodes = [
            n
            for n in evidence_graph.get_nodes_by_type(NodeType.INVARIANT)
            if isinstance(n, InvariantNode)
        ]
        tx_nodes = [
            n for n in evidence_graph.get_nodes_by_type(NodeType.TX) if isinstance(n, TxNode)
        ]

        target_contract = (
            code_nodes[0].contract_name
            if code_nodes
            else (state_nodes[0].contract_address if state_nodes else "UnknownContract")
        )

        vuln_class = "STATE_INVARIANT_VIOLATION"
        pointers: List[str] = []

        for c_node in code_nodes:
            if ".call" in c_node.source_code or "delegatecall" in c_node.source_code:
                vuln_class = "REENTRANCY_OR_UNCHECKED_EXTERNAL_CALL"
                pointers.append(c_node.node_id)
                break

        if not pointers and code_nodes:
            pointers.append(code_nodes[0].node_id)
        if state_nodes:
            pointers.append(state_nodes[0].node_id)
        if inv_nodes:
            pointers.append(inv_nodes[0].node_id)
        if tx_nodes and not pointers:
            pointers.append(tx_nodes[0].node_id)

        precondition = (
            f"Pre-existing state on {target_contract} allows external call before state update"
            if state_nodes
            else f"Entrypoint invocation on {target_contract}"
        )

        return [
            VulnerabilityHypothesis(
                hypothesis_id="H-01",
                vulnerability_class=vuln_class,
                precondition=precondition,
                target_contract=target_contract,
                evidence_pointers=pointers,
            )
        ]

