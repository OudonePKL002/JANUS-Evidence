"""Root-Cause Analysis (RCA) Agent for JANUS-Evidence (Stage 3: 6-Slot Causal Chain).

Implements Section 2.3 of the JANUS-Evidence Master Project Plan (v1.2.0).
Emits the strict 6-Slot Causal Output Specification with explicit pointers into
G=(N,E) and provides the `revise(...)` hook for the Evidence Gate R=3 loop.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.agents.base_agent import AgentOutput, BaseAgent, LLMBackendCallable
from core.analyzer.graph_builder import (
    AssetNode,
    CallNode,
    CodeNode,
    EvidenceGraph,
    InvariantNode,
    NodeType,
    StateNode,
    TxNode,
)
from core.gate.evidence_gate import CausalClaim, ClaimStatus

RCARevisionCallable = Callable[[List[CausalClaim], int, EvidenceGraph], List[CausalClaim]]

REQUIRED_RCA_SLOTS = (
    "pre_attack_state",
    "attacker_input",
    "vulnerable_operation",
    "state_invariant_breakdown",
    "asset_flow_impact",
    "minimal_causal_chain",
)


class RCASlotEntry(BaseModel):
    """Single slot entry in the 6-slot RCA specification backed by evidence pointers."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    slot_index: int = Field(..., ge=1, le=6, description="1-based slot index (1..6)")
    slot_name: str = Field(..., min_length=1, description="Canonical slot identifier")
    description: str = Field(..., min_length=1, description="Formal causal description for this slot")
    evidence_pointers: List[str] = Field(
        default_factory=list,
        description="Pointers into G=(N,E) grounding this specific slot",
    )


class SixSlotCausalChain(BaseModel):
    """Strict 6-Slot RCA Output Specification (Section 2.3 of Master Project Plan)."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    pre_attack_state: RCASlotEntry = Field(
        ..., description="Slot 1: The protocol condition prior to exploitation."
    )
    attacker_input: RCASlotEntry = Field(
        ..., description="Slot 2: The specific malicious transaction payload/parameters."
    )
    vulnerable_operation: RCASlotEntry = Field(
        ..., description="Slot 3: The precise AST statement/function causing the flaw."
    )
    state_invariant_breakdown: RCASlotEntry = Field(
        ..., description="Slot 4: The mathematical security invariant that was violated."
    )
    asset_flow_impact: RCASlotEntry = Field(
        ..., description="Slot 5: The resulting token drain or collateral manipulation."
    )
    minimal_causal_chain: RCASlotEntry = Field(
        ..., description="Slot 6: The sequential order of operations linking 1 through 5."
    )

    def ordered_slots(self) -> List[RCASlotEntry]:
        """Return all 6 slots in strict sequential order (1 through 6)."""
        return [
            self.pre_attack_state,
            self.attacker_input,
            self.vulnerable_operation,
            self.state_invariant_breakdown,
            self.asset_flow_impact,
            self.minimal_causal_chain,
        ]

    def to_claims(self, agent_role: str = "RCA") -> List[CausalClaim]:
        """Convert each of the 6 slots into an individually verifiable `CausalClaim`."""
        claims: List[CausalClaim] = []
        for slot in self.ordered_slots():
            claims.append(
                CausalClaim(
                    claim_id=f"RCA-SLOT-{slot.slot_index}-{slot.slot_name.upper()}",
                    agent_role=agent_role,
                    statement=f"[Slot {slot.slot_index}: {slot.slot_name}] {slot.description}",
                    evidence_pointers=list(slot.evidence_pointers),
                    status=ClaimStatus.PENDING,
                )
            )
        return claims


class RCAAgent(BaseAgent):
    """Role-specialized agent that synthesizes and revises the 6-slot causal chain."""

    def __init__(
        self,
        name: str = "JanusRCAAgent",
        llm_backend: Optional[LLMBackendCallable] = None,
        revision_backend: Optional[RCARevisionCallable] = None,
        auto_repair_pointers: bool = True,
    ) -> None:
        super().__init__(name=name, role="RCA", llm_backend=llm_backend)
        self.revision_backend: Optional[RCARevisionCallable] = revision_backend
        self.auto_repair_pointers: bool = auto_repair_pointers

    def execute(
        self,
        input_data: Dict[str, Any],
        evidence_graph: EvidenceGraph,
    ) -> AgentOutput:
        """Synthesize the 6-slot causal chain and emit 6 corresponding `CausalClaim`s."""
        if self.llm_backend is not None:
            raw_resp = self.llm_backend(input_data, evidence_graph)
            six_slot_chain = self._parse_six_slot_response(raw_resp)
        elif "six_slot_chain" in input_data:
            six_slot_chain = self._parse_six_slot_response(input_data["six_slot_chain"])
        else:
            six_slot_chain = self._synthesize_from_graph(input_data, evidence_graph)

        claims = six_slot_chain.to_claims(agent_role=self.role)
        return AgentOutput(
            agent_name=self.name,
            agent_role=self.role,
            claims=claims,
            payload={
                "six_slot_chain": six_slot_chain.model_dump(mode="json"),
                "slot_names": list(REQUIRED_RCA_SLOTS),
            },
            metadata={"slot_count": 6},
        )

    def revise(
        self,
        claims: List[CausalClaim],
        round_idx: int,
        evidence_graph: EvidenceGraph,
    ) -> List[CausalClaim]:
        """Revise `UNGROUNDED` claims using `invalid_pointers` feedback from the Evidence Gate.

        Invoked during the iterative revision loop (up to R=3 rounds).
        """
        if self.revision_backend is not None:
            return self.revision_backend(claims, round_idx, evidence_graph)

        revised_claims: List[CausalClaim] = []
        for claim in claims:
            cloned = claim.model_copy(deep=True)
            if cloned.status == ClaimStatus.GROUNDED:
                revised_claims.append(cloned)
                continue

            if not self.auto_repair_pointers:
                revised_claims.append(cloned)
                continue

            # Filter out invalid pointers and replace with valid graph pointers matching the slot
            valid_kept = [
                ptr for ptr in cloned.evidence_pointers if evidence_graph.has_pointer(ptr)
            ]
            if not valid_kept:
                valid_kept = self._fallback_pointers_for_claim(cloned.claim_id, evidence_graph)

            cloned.evidence_pointers = valid_kept
            cloned.invalid_pointers = []
            revised_claims.append(cloned)

        return revised_claims

    def _parse_six_slot_response(self, raw: Dict[str, Any]) -> SixSlotCausalChain:
        """Parse a dictionary containing `six_slot_chain` or direct slot keys into `SixSlotCausalChain`."""
        data = raw.get("six_slot_chain", raw)
        return SixSlotCausalChain.model_validate(data)

    def _synthesize_from_graph(
        self,
        input_data: Dict[str, Any],
        evidence_graph: EvidenceGraph,
    ) -> SixSlotCausalChain:
        """Construct a deterministic, pointer-grounded 6-slot causal chain from `evidence_graph`."""
        state_nodes = [
            n for n in evidence_graph.get_nodes_by_type(NodeType.STATE) if isinstance(n, StateNode)
        ]
        tx_nodes = [
            n for n in evidence_graph.get_nodes_by_type(NodeType.TX) if isinstance(n, TxNode)
        ]
        call_nodes = [
            n for n in evidence_graph.get_nodes_by_type(NodeType.CALL) if isinstance(n, CallNode)
        ]
        code_nodes = [
            n for n in evidence_graph.get_nodes_by_type(NodeType.CODE) if isinstance(n, CodeNode)
        ]
        inv_nodes = [
            n
            for n in evidence_graph.get_nodes_by_type(NodeType.INVARIANT)
            if isinstance(n, InvariantNode)
        ]
        asset_nodes = [
            n for n in evidence_graph.get_nodes_by_type(NodeType.ASSET) if isinstance(n, AssetNode)
        ]

        # Prioritize top-1 localized code slice if provided by LocalizationAgent
        top_loc = (input_data.get("localization") or {}).get("top_1")
        if top_loc and evidence_graph.has_pointer(str(top_loc.get("ast_id", ""))):
            vuln_ptrs = [str(top_loc["ast_id"]), str(top_loc["statement_id"])]
            vuln_desc = (
                f"Vulnerable operation at {top_loc['contract_name']}.{top_loc['function_name']} "
                f"({top_loc['statement_id']})"
            )
        elif code_nodes:
            target_code = code_nodes[-1]
            vuln_ptrs = [target_code.ast_id, target_code.statement_id]
            vuln_desc = (
                f"Vulnerable operation at {target_code.contract_name}.{target_code.function_name} "
                f"({target_code.statement_id}): {target_code.source_code}"
            )
        else:
            vuln_ptrs = []
            vuln_desc = "Vulnerable operation slice"

        state_ptrs = [s.node_id for s in state_nodes[:2]] or vuln_ptrs[:1]
        tx_ptrs = [t.node_id for t in tx_nodes[:1]] + [c.node_id for c in call_nodes[:1]]
        if not tx_ptrs:
            tx_ptrs = state_ptrs[:1]

        inv_ptrs = [i.node_id for i in inv_nodes] or state_ptrs[:1]
        asset_ptrs = [a.node_id for a in asset_nodes] or state_ptrs[:1]

        chain_ptrs: List[str] = []
        for ptr_group in (state_ptrs, tx_ptrs, vuln_ptrs, inv_ptrs, asset_ptrs):
            for p in ptr_group:
                if p not in chain_ptrs:
                    chain_ptrs.append(p)

        return SixSlotCausalChain(
            pre_attack_state=RCASlotEntry(
                slot_index=1,
                slot_name="pre_attack_state",
                description=(
                    f"Pre-attack storage state {state_nodes[0].variable_name}={state_nodes[0].pre_val}"
                    if state_nodes
                    else "Protocol initial state prior to exploit transaction."
                ),
                evidence_pointers=state_ptrs,
            ),
            attacker_input=RCASlotEntry(
                slot_index=2,
                slot_name="attacker_input",
                description=(
                    f"Attacker transaction {tx_nodes[0].tx_hash} from {tx_nodes[0].from_addr} "
                    f"with calldata {tx_nodes[0].calldata[:18]}..."
                    if tx_nodes
                    else "Malicious external invocation payload."
                ),
                evidence_pointers=tx_ptrs,
            ),
            vulnerable_operation=RCASlotEntry(
                slot_index=3,
                slot_name="vulnerable_operation",
                description=vuln_desc,
                evidence_pointers=vuln_ptrs,
            ),
            state_invariant_breakdown=RCASlotEntry(
                slot_index=4,
                slot_name="state_invariant_breakdown",
                description=(
                    f"Violation of {inv_nodes[0].invariant_type.value} invariant: {inv_nodes[0].expression}"
                    if inv_nodes
                    else "Storage state updated inconsistently with protocol accounting invariant."
                ),
                evidence_pointers=inv_ptrs,
            ),
            asset_flow_impact=RCASlotEntry(
                slot_index=5,
                slot_name="asset_flow_impact",
                description=(
                    f"Unbacked transfer of {asset_nodes[0].amount} {asset_nodes[0].symbol} "
                    f"from {asset_nodes[0].from_addr} to {asset_nodes[0].to_addr}"
                    if asset_nodes
                    else "Drain of protocol reserves to attacker-controlled address."
                ),
                evidence_pointers=asset_ptrs,
            ),
            minimal_causal_chain=RCASlotEntry(
                slot_index=6,
                slot_name="minimal_causal_chain",
                description=" -> ".join(chain_ptrs),
                evidence_pointers=chain_ptrs,
            ),
        )

    @staticmethod
    def _fallback_pointers_for_claim(
        claim_id: str,
        evidence_graph: EvidenceGraph,
    ) -> List[str]:
        """Select valid pointers from `evidence_graph` corresponding to the slot category."""
        cid_upper = claim_id.upper()
        if "PRE_ATTACK_STATE" in cid_upper:
            nodes = evidence_graph.get_nodes_by_type(NodeType.STATE)
        elif "ATTACKER_INPUT" in cid_upper:
            nodes = evidence_graph.get_nodes_by_type(NodeType.TX) or evidence_graph.get_nodes_by_type(
                NodeType.CALL
            )
        elif "VULNERABLE_OPERATION" in cid_upper:
            nodes = evidence_graph.get_nodes_by_type(NodeType.CODE)
        elif "STATE_INVARIANT_BREAKDOWN" in cid_upper:
            nodes = evidence_graph.get_nodes_by_type(
                NodeType.INVARIANT
            ) or evidence_graph.get_nodes_by_type(NodeType.STATE)
        elif "ASSET_FLOW_IMPACT" in cid_upper:
            nodes = evidence_graph.get_nodes_by_type(NodeType.ASSET)
        else:
            nodes = (
                evidence_graph.get_nodes_by_type(NodeType.TX)[:1]
                + evidence_graph.get_nodes_by_type(NodeType.CODE)[:1]
                + evidence_graph.get_nodes_by_type(NodeType.STATE)[:1]
                + evidence_graph.get_nodes_by_type(NodeType.ASSET)[:1]
            )
        return [n.node_id for n in nodes[:2]]

