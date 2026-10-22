"""Unit tests for the formal Evidence Gate and Revision Loop (R=3) in core/gate/evidence_gate.py."""

from typing import List

import pytest

from core.analyzer.graph_builder import (
    AssetNode,
    CallNode,
    CallType,
    CodeNode,
    EdgeType,
    EvidenceGraph,
    InvariantNode,
    InvariantType,
    StateNode,
    TxNode,
)
from core.gate.evidence_gate import (
    CausalClaim,
    ClaimStatus,
    EvidenceGate,
    GateDecision,
    GateVerdict,
)


@pytest.fixture
def populated_graph() -> EvidenceGraph:
    """Create a populated EvidenceGraph G=(N,E) for testing pointer verification."""
    graph = EvidenceGraph(incident_id="INC-GATE-001")

    graph.add_node(
        TxNode(
            tx_hash="0xtx001",
            block_number=19000000,
            from_addr="0xAttacker",
            to_addr="0xRouter",
            calldata="0x12345678",
            value=0,
            gas_used=210000,
            status=1,
        )
    )
    graph.add_node(
        CallNode(
            call_id="CALL-1",
            parent_call_id=None,
            caller="0xRouter",
            callee="0xPool",
            value=0,
            function_selector="0xabcdef01",
            call_type=CallType.CALL,
        )
    )
    graph.add_node(
        CodeNode(
            ast_id="AST-200",
            file_path="contracts/Pool.sol",
            contract_name="Pool",
            function_name="flashSwap",
            statement_id="STMT-200-5",
            source_code="reserve0 = balance0;",
            line_range=(88, 88),
        )
    )
    graph.add_node(
        StateNode(
            state_id="STATE-RESERVE-0",
            contract_address="0xPool",
            storage_slot="0x08",
            variable_name="reserve0",
            pre_val="5000000",
            post_val="100",
            block_number=19000000,
        )
    )
    graph.add_node(
        AssetNode(
            asset_id="ASSET-DRAIN-1",
            token_address="0xUSDC",
            symbol="USDC",
            from_addr="0xPool",
            to_addr="0xAttacker",
            amount=4999900,
            flow_type="TRANSFER",
        )
    )
    graph.add_node(
        InvariantNode(
            invariant_id="INV-K-01",
            invariant_type=InvariantType.CONSTANT_PRODUCT,
            expression="reserve0 * reserve1 >= k_pre",
            violation_status=True,
        )
    )

    graph.add_edge("0xtx001", "CALL-1", EdgeType.CALLS)
    graph.add_edge("CALL-1", "AST-200", EdgeType.DEPENDS_ON)
    graph.add_edge("AST-200", "STATE-RESERVE-0", EdgeType.MODIFIES_STATE)
    graph.add_edge("CALL-1", "ASSET-DRAIN-1", EdgeType.TRANSFERS_ASSET)
    graph.add_edge("STATE-RESERVE-0", "INV-K-01", EdgeType.VIOLATES)

    return graph


def test_verify_claim_grounded(populated_graph: EvidenceGraph) -> None:
    """Valid node IDs, statement IDs, and edge pointers must transition claim to GROUNDED."""
    gate = EvidenceGate(populated_graph)

    claim = CausalClaim(
        claim_id="CLAIM-01",
        agent_role="RCA",
        statement="flashSwap modifies reserve0 without updating constant product invariant.",
        evidence_pointers=[
            "AST-200",
            "STMT-200-5",
            "STATE-RESERVE-0",
            "AST-200->MODIFIES_STATE->STATE-RESERVE-0",
        ],
    )
    assert claim.status == ClaimStatus.PENDING

    verified = gate.verify_claim(claim)
    assert verified.status == ClaimStatus.GROUNDED
    assert verified.invalid_pointers == []


def test_verify_claim_ungrounded_on_hallucinated_or_empty_pointers(
    populated_graph: EvidenceGraph,
) -> None:
    """Hallucinated or empty pointers must transition claim to UNGROUNDED."""
    gate = EvidenceGate(populated_graph)

    hallucinated_claim = CausalClaim(
        claim_id="CLAIM-HALLUCINATED",
        agent_role="Localization",
        statement="Reentrancy in non-existent AST node.",
        evidence_pointers=["AST-200", "AST-HALLUCINATED-999", "CALL-1->VIOLATES->AST-200"],
    )
    verified = gate.verify_claim(hallucinated_claim)
    assert verified.status == ClaimStatus.UNGROUNDED
    assert verified.invalid_pointers == ["AST-HALLUCINATED-999", "CALL-1->VIOLATES->AST-200"]

    empty_claim = CausalClaim(
        claim_id="CLAIM-EMPTY",
        agent_role="Auditor",
        statement="Unbacked intuition without pointers.",
        evidence_pointers=[],
    )
    verified_empty = gate.verify_claim(empty_claim)
    assert verified_empty.status == ClaimStatus.UNGROUNDED


def test_evaluate_causal_chain_immediate_verified_for_exploit(
    populated_graph: EvidenceGraph,
) -> None:
    """When all claims in the chain have valid pointers, return VERIFIED_FOR_EXPLOIT in round 1."""
    gate = EvidenceGate(populated_graph)

    claims = [
        CausalClaim(
            claim_id="SLOT-1",
            agent_role="Auditor",
            statement="Initial attacker transaction invokes Pool via Router.",
            evidence_pointers=["0xtx001", "CALL-1", "0xtx001->CALLS->CALL-1"],
        ),
        CausalClaim(
            claim_id="SLOT-2",
            agent_role="Localization",
            statement="Vulnerable statement in Pool.flashSwap.",
            evidence_pointers=["AST-200", "STMT-200-5"],
        ),
        CausalClaim(
            claim_id="SLOT-3",
            agent_role="RCA",
            statement="State mutation violates constant product invariant and drains USDC.",
            evidence_pointers=[
                "STATE-RESERVE-0",
                "INV-K-01",
                "ASSET-DRAIN-1",
                "STATE-RESERVE-0->VIOLATES->INV-K-01",
            ],
        ),
    ]

    verdict = gate.evaluate_causal_chain(claims, max_rounds=3)
    assert verdict == GateVerdict.VERIFIED_FOR_EXPLOIT
    assert verdict.verdict == GateDecision.VERIFIED_FOR_EXPLOIT
    assert verdict.is_verified is True
    assert verdict.rounds_used == 1
    assert verdict.ungrounded_claim_ids == []
    assert all(c.status == ClaimStatus.GROUNDED for c in verdict.claims)


def test_evaluate_causal_chain_inconclusive_after_three_failed_rounds(
    populated_graph: EvidenceGraph,
) -> None:
    """When ungrounded claims remain after R=3 rounds, gate must abstain with INCONCLUSIVE."""
    gate = EvidenceGate(populated_graph)

    claims = [
        CausalClaim(
            claim_id="CLAIM-VALID",
            agent_role="Localization",
            statement="Valid localization slice.",
            evidence_pointers=["AST-200"],
        ),
        CausalClaim(
            claim_id="CLAIM-BAD",
            agent_role="RCA",
            statement="Persistent hallucinated invariant pointer.",
            evidence_pointers=["INV-DOES-NOT-EXIST"],
        ),
    ]

    revision_attempts: List[int] = []

    def failing_revision_loop(current: List[CausalClaim], round_idx: int) -> List[CausalClaim]:
        revision_attempts.append(round_idx)
        # Agent keeps proposing an invalid pointer across all retries
        for c in current:
            if c.claim_id == "CLAIM-BAD":
                c.evidence_pointers = [f"INV-HALLUCINATED-ROUND-{round_idx}"]
        return current

    verdict = gate.evaluate_causal_chain(
        claims, max_rounds=3, revision_callback=failing_revision_loop
    )

    assert verdict == GateVerdict.INCONCLUSIVE
    assert verdict.verdict == GateDecision.INCONCLUSIVE
    assert verdict.is_verified is False
    assert verdict.rounds_used == 3
    assert revision_attempts == [1, 2]
    assert verdict.ungrounded_claim_ids == ["CLAIM-BAD"]

    status_by_id = {c.claim_id: c.status for c in verdict.claims}
    assert status_by_id["CLAIM-VALID"] == ClaimStatus.GROUNDED
    assert status_by_id["CLAIM-BAD"] == ClaimStatus.INCONCLUSIVE


def test_evaluate_causal_chain_succeeds_on_revision_within_r3(
    populated_graph: EvidenceGraph,
) -> None:
    """When an ungrounded claim is repaired during the R=3 revision loop, return VERIFIED_FOR_EXPLOIT."""
    gate = EvidenceGate(populated_graph)

    claims = [
        CausalClaim(
            claim_id="CLAIM-REPAIRABLE",
            agent_role="RCA",
            statement="Initially cites wrong AST ID, repaired on round 2.",
            evidence_pointers=["AST-WRONG-ID"],
        )
    ]

    def repair_on_second_round(current: List[CausalClaim], round_idx: int) -> List[CausalClaim]:
        for c in current:
            if c.claim_id == "CLAIM-REPAIRABLE":
                if round_idx == 1:
                    # Still wrong after 1st revision (evaluated in round 2)
                    c.evidence_pointers = ["AST-STILL-WRONG"]
                elif round_idx == 2:
                    # Repaired on 2nd revision (evaluated in round 3)
                    c.evidence_pointers = ["AST-200", "STATE-RESERVE-0"]
        return current

    verdict = gate.evaluate_causal_chain(
        claims, max_rounds=3, revision_callback=repair_on_second_round
    )

    assert verdict == GateVerdict.VERIFIED_FOR_EXPLOIT
    assert verdict.is_verified is True
    assert verdict.rounds_used == 3
    assert verdict.ungrounded_claim_ids == []
    assert verdict.claims[0].status == ClaimStatus.GROUNDED

