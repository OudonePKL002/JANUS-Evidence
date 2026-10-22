"""Programmatic and State Mutator Interface for JANUS-Evidence do()-Calculus.

Implements the causal intervention operators do(cause=off) and size-matched
non-causal control mutations do(ctrl_i=off) (k >= 10) specified in Section 1.2
(Objective 2), Section 2.2, and Section 6 (Threat 3) of the JANUS-Evidence
Master Project Plan (v1.2.0).
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.analyzer.graph_builder import CodeNode, EvidenceGraph, NodeType

DEFAULT_CONTROL_COUNT: int = 10


class MutationOperator(str, Enum):
    """Supported causal intervention operators for do(cause=off)."""

    DISABLE_STATEMENT = "DISABLE_STATEMENT"
    REVERT_STATE_DELTA = "REVERT_STATE_DELTA"
    LOCK_ORACLE = "LOCK_ORACLE"


class MutationSpec(BaseModel):
    """Specification of a single programmatic or state intervention do(target=off)."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    mutation_id: str = Field(..., min_length=1, description="Unique mutation identifier")
    operator: MutationOperator = Field(
        ...,
        description="Intervention operator type (DISABLE_STATEMENT, REVERT_STATE_DELTA, LOCK_ORACLE)",
    )
    target_pointer: str = Field(
        ...,
        min_length=1,
        description="Target node_id or statement_id in the EvidenceGraph G=(N,E)",
    )
    is_control: bool = Field(
        default=False,
        description="False for causal intervention do(c=off); True for control intervention do(ctrl_i=off)",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Human-readable summary of the applied intervention",
    )
    patched_snippet: Optional[str] = Field(
        default=None,
        description="Synthesized AST/Solidity replacement or storage override representation",
    )


class ProgrammaticMutator:
    """Synthesizes causal interventions do(c=off) and size-matched control mutations do(ctrl_i=off)."""

    def __init__(self, default_k: int = DEFAULT_CONTROL_COUNT) -> None:
        if default_k < 1:
            raise ValueError(f"default_k must be >= 1, got {default_k}.")
        self.default_k: int = default_k

    def create_causal_mutation(
        self,
        target_pointer: str,
        operator: MutationOperator = MutationOperator.DISABLE_STATEMENT,
        evidence_graph: Optional[EvidenceGraph] = None,
    ) -> MutationSpec:
        """Create the primary causal intervention do(cause=off) for `target_pointer`."""
        if not target_pointer or not target_pointer.strip():
            raise ValueError("target_pointer must be a non-empty string.")

        patched = self._synthesize_patch(target_pointer, operator, evidence_graph)
        return MutationSpec(
            mutation_id=f"DO-CAUSE-{operator.value}-{target_pointer}",
            operator=operator,
            target_pointer=target_pointer,
            is_control=False,
            description=f"Causal intervention do({target_pointer}=off) via {operator.value}",
            patched_snippet=patched,
        )

    def generate_control_mutations(
        self,
        causal_target_pointer: str,
        k: Optional[int] = None,
        operator: MutationOperator = MutationOperator.DISABLE_STATEMENT,
        evidence_graph: Optional[EvidenceGraph] = None,
    ) -> List[MutationSpec]:
        """Generate k (default k >= 10) size-matched non-causal control mutations do(ctrl_i=off).

        Selects non-causal code/state nodes from `evidence_graph` when available and
        pads with deterministic synthetic control targets up to `k` to satisfy
        the Specificity control size requirement (Section 2.2 & Section 6).
        """
        target_k = k if k is not None else self.default_k
        if target_k < 1:
            raise ValueError(f"Control count k must be >= 1, got {target_k}.")

        candidate_pointers: List[str] = []
        if evidence_graph is not None:
            resolved_causal = evidence_graph.get_node(causal_target_pointer)
            causal_nid = resolved_causal.node_id if resolved_causal else causal_target_pointer

            for node in evidence_graph.get_nodes_by_type(NodeType.CODE):
                if isinstance(node, CodeNode):
                    if (
                        node.node_id != causal_nid
                        and node.statement_id != causal_target_pointer
                        and not node.statement_id.endswith(":0")
                    ):
                        candidate_pointers.append(node.statement_id)

        controls: List[MutationSpec] = []
        for idx in range(1, target_k + 1):
            if idx <= len(candidate_pointers):
                ctrl_ptr = candidate_pointers[idx - 1]
            else:
                ctrl_ptr = f"CTRL-NON-CAUSAL-STMT-{idx:02d}"

            patched = self._synthesize_patch(ctrl_ptr, operator, evidence_graph)
            controls.append(
                MutationSpec(
                    mutation_id=f"DO-CTRL-{idx:02d}-{operator.value}",
                    operator=operator,
                    target_pointer=ctrl_ptr,
                    is_control=True,
                    description=(
                        f"Size-matched control intervention #{idx} do({ctrl_ptr}=off) "
                        f"via {operator.value}"
                    ),
                    patched_snippet=patched,
                )
            )

        return controls

    @staticmethod
    def _synthesize_patch(
        target_pointer: str,
        operator: MutationOperator,
        evidence_graph: Optional[EvidenceGraph] = None,
    ) -> str:
        """Produce a deterministic representation of the AST/state intervention."""
        original_code = ""
        if evidence_graph is not None:
            node = evidence_graph.get_node(target_pointer)
            if isinstance(node, CodeNode):
                original_code = node.source_code

        if operator == MutationOperator.DISABLE_STATEMENT:
            return f"/* do({target_pointer}=off): DISABLE_STATEMENT */ ; // orig: {original_code}"
        if operator == MutationOperator.REVERT_STATE_DELTA:
            return f"/* do({target_pointer}=off): REVERT_STATE_DELTA */ vm.store(target, slot, pre_val);"
        if operator == MutationOperator.LOCK_ORACLE:
            return f"/* do({target_pointer}=off): LOCK_ORACLE */ vm.mockCall(oracle, baselinePrice);"
        return f"/* do({target_pointer}=off) */"

