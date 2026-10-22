"""Localization Agent for JANUS-Evidence (Stage 2: Vulnerable Slice Localization L).

Consumes Auditor hypotheses H and the EvidenceGraph G=(N,E) to identify Top-k
vulnerable program locations L (contract, function, line_range, statement_id).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from core.agents.base_agent import AgentOutput, BaseAgent, LLMBackendCallable
from core.analyzer.graph_builder import CodeNode, EvidenceGraph, NodeType
from core.gate.evidence_gate import CausalClaim


class LocalizedLocation(BaseModel):
    """Represents a ranked candidate vulnerable code location L in G=(N,E)."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    location_id: str = Field(..., min_length=1, description="Unique localization candidate ID")
    rank: int = Field(..., ge=1, description="1-based ranking (1 = Top-1 candidate)")
    contract_name: str = Field(..., min_length=1, description="Enclosing contract name")
    function_name: str = Field(..., min_length=1, description="Enclosing function name")
    statement_id: str = Field(
        ...,
        min_length=1,
        description="Canonical statement slice pointer (contract:function:stmt_idx)",
    )
    ast_id: str = Field(..., min_length=1, description="Primary CodeNode AST identifier")
    line_range: Tuple[int, int] = Field(..., description="1-based inclusive line range")
    rationale: str = Field(..., min_length=1, description="Causal localization rationale")
    evidence_pointers: List[str] = Field(
        default_factory=list,
        description="Pointers into G=(N,E) grounding this localization candidate",
    )


class LocalizationAgent(BaseAgent):
    """Role-specialized agent that narrows hypotheses H down to Top-k program locations L."""

    def __init__(
        self,
        name: str = "JanusLocalizationAgent",
        top_k: int = 3,
        llm_backend: Optional[LLMBackendCallable] = None,
    ) -> None:
        super().__init__(name=name, role="Localization", llm_backend=llm_backend)
        self.top_k: int = max(1, top_k)

    def execute(
        self,
        input_data: Dict[str, Any],
        evidence_graph: EvidenceGraph,
    ) -> AgentOutput:
        """Identify Top-k vulnerable code slices L and emit grounded localization claims."""
        if self.llm_backend is not None:
            raw_resp = self.llm_backend(input_data, evidence_graph)
            locations = [
                LocalizedLocation.model_validate(loc)
                for loc in raw_resp.get("locations", [])[: self.top_k]
            ]
        elif "locations" in input_data:
            locations = [
                LocalizedLocation.model_validate(loc)
                for loc in input_data["locations"][: self.top_k]
            ]
        else:
            locations = self._heuristic_localize(evidence_graph)

        claims: List[CausalClaim] = []
        for loc in locations:
            claims.append(
                self.build_claim(
                    claim_id=f"CLAIM-LOC-{loc.location_id}",
                    statement=(
                        f"Top-{loc.rank} vulnerable slice at {loc.contract_name}.{loc.function_name} "
                        f"({loc.statement_id}, lines {loc.line_range[0]}-{loc.line_range[1]}): {loc.rationale}"
                    ),
                    evidence_pointers=loc.evidence_pointers,
                )
            )

        return AgentOutput(
            agent_name=self.name,
            agent_role=self.role,
            claims=claims,
            payload={
                "locations": [loc.model_dump(mode="json") for loc in locations],
                "top_1": locations[0].model_dump(mode="json") if locations else None,
            },
            metadata={"top_k": self.top_k, "candidate_count": len(locations)},
        )

    def _heuristic_localize(
        self,
        evidence_graph: EvidenceGraph,
    ) -> List[LocalizedLocation]:
        """Deterministic graph-backed localization ranking for offline testing."""
        code_nodes = [
            n for n in evidence_graph.get_nodes_by_type(NodeType.CODE) if isinstance(n, CodeNode)
        ]

        # Score CodeNodes: prioritize external calls (.call / delegatecall) and state writes
        scored: List[Tuple[int, CodeNode]] = []
        for c_node in code_nodes:
            score = 0
            src = c_node.source_code
            if ".call" in src or "delegatecall" in src:
                score += 100
            if "=" in src and not src.startswith("function "):
                score += 50
            if not c_node.statement_id.endswith(":0"):
                score += 10
            scored.append((score, c_node))

        scored.sort(key=lambda item: (-item[0], item[1].line_range[0]))
        selected = [node for _, node in scored[: self.top_k]]

        locations: List[LocalizedLocation] = []
        for rank_idx, node in enumerate(selected, start=1):
            locations.append(
                LocalizedLocation(
                    location_id=f"L-{rank_idx:02d}",
                    rank=rank_idx,
                    contract_name=node.contract_name,
                    function_name=node.function_name,
                    statement_id=node.statement_id,
                    ast_id=node.ast_id,
                    line_range=node.line_range,
                    rationale=f"Critical operation in {node.contract_name}.{node.function_name}: `{node.source_code}`",
                    evidence_pointers=[node.ast_id, node.statement_id],
                )
            )
        return locations

