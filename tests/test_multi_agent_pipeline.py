"""Unit tests for the 4-Agent Pipeline and Evidence Gate R=3 Integration in Step 1.5."""

from typing import Any, Dict, List

import pytest

from core.agents import (
    AuditorAgent,
    ExploitAgent,
    JanusPipeline,
    LocalizationAgent,
    RCAAgent,
    REQUIRED_RCA_SLOTS,
)
from core.analyzer import EvidenceGraph, build_evidence_graph
from core.gate import CausalClaim, ClaimStatus, GateDecision, GateVerdict

SAMPLE_VAULT_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrantVault {
    mapping(address => uint256) public shares;
    uint256 public totalReserve;

    function withdrawAll(uint256 amount) external {
        uint256 bal = shares[msg.sender];
        require(bal >= amount, "Insufficient shares");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");
        shares[msg.sender] = bal - amount;
        totalReserve = totalReserve - amount;
    }
}
"""


@pytest.fixture
def incident_graph() -> EvidenceGraph:
    """Build a realistic EvidenceGraph G=(N,E) for a reentrancy exploit incident."""
    trace_payload: Dict[str, Any] = {
        "incident_id": "INC-PIPELINE-001",
        "tx": {
            "tx_hash": "0xfeedface0000111122223333444455556666777788889999aaaabbbbccccdddd",
            "block_number": 19800500,
            "from_addr": "0xAttackerEOA",
            "to_addr": "0xAttackerExploit",
            "calldata": "0x853828b60000000000000000000000000000000000000000000000000de0b6b3a7640000",
            "value": 0,
            "gas_used": 412000,
            "status": 1,
        },
        "call_trace": {
            "call_id": "CALL-1",
            "type": "CALL",
            "from": "0xAttackerExploit",
            "to": "0xReentrantVault",
            "value": 0,
            "input": "0x853828b6",
            "calls": [
                {
                    "call_id": "CALL-2",
                    "type": "CALL",
                    "from": "0xReentrantVault",
                    "to": "0xAttackerExploit",
                    "value": 10000000000000000000,
                    "input": "0x",
                }
            ],
        },
        "state_diffs": [
            {
                "state_id": "STATE:0xReentrantVault:0x00",
                "contract_address": "0xReentrantVault",
                "storage_slot": "0x00",
                "variable_name": "shares[0xAttackerExploit]",
                "pre_val": "1000000000000000000",
                "post_val": "0",
                "block_number": 19800500,
            },
            {
                "state_id": "STATE:0xReentrantVault:0x01",
                "contract_address": "0xReentrantVault",
                "storage_slot": "0x01",
                "variable_name": "totalReserve",
                "pre_val": "10000000000000000000",
                "post_val": "0",
                "block_number": 19800500,
            },
        ],
        "asset_transfers": [
            {
                "asset_id": "ASSET-ETH-1",
                "token_address": "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
                "symbol": "ETH",
                "from_addr": "0xReentrantVault",
                "to_addr": "0xAttackerExploit",
                "amount": 10000000000000000000,
                "flow_type": "TRANSFER",
                "call_id": "CALL-2",
            }
        ],
        "invariants": [
            {
                "invariant_id": "INV-SOLVENCY-VAULT",
                "invariant_type": "SOLVENCY",
                "expression": "address(ReentrantVault).balance >= totalReserve",
                "violation_status": True,
                "violated_by": "STATE:0xReentrantVault:0x01",
            }
        ],
    }

    return build_evidence_graph(
        contract_source=SAMPLE_VAULT_SOURCE,
        trace_data=trace_payload,
        file_path="contracts/ReentrantVault.sol",
    )


def test_case_a_coordinated_pipeline_verified_for_exploit(
    incident_graph: EvidenceGraph,
) -> None:
    """Case A: Coordinated 4-agent pipeline produces grounded 6-slot chain -> VERIFIED_FOR_EXPLOIT."""
    pipeline = JanusPipeline()
    result = pipeline.run(incident_graph)

    assert result.status == GateVerdict.VERIFIED_FOR_EXPLOIT
    assert result.is_verified is True
    assert result.gate_verdict.verdict == GateDecision.VERIFIED_FOR_EXPLOIT
    assert result.gate_verdict.rounds_used == 1
    assert len(result.verified_claims) == 6
    assert all(c.status == ClaimStatus.GROUNDED for c in result.verified_claims)

    # Verify all 6 slots exist in RCA payload
    six_slots = result.rca_output.payload["six_slot_chain"]
    for slot_key in REQUIRED_RCA_SLOTS:
        assert slot_key in six_slots
        assert len(six_slots[slot_key]["evidence_pointers"]) >= 1

    # Verify Localization Top-1 identified the external call slice
    top_1 = result.localization_output.payload["top_1"]
    assert top_1 is not None
    assert top_1["contract_name"] == "ReentrantVault"
    assert top_1["function_name"] == "withdrawAll"
    assert top_1["statement_id"] == "ReentrantVault:withdrawAll:3"

    # Verify ExploitAgent executed and generated a valid replay plan
    assert result.exploit_output is not None
    exploit_plan = result.exploit_output.payload["exploit_plan"]
    assert exploit_plan["incident_id"] == "INC-PIPELINE-001"
    assert exploit_plan["fork_block_number"] == 19800499
    assert exploit_plan["expected_profit_wei"] == 10000000000000000000
    assert incident_graph.has_pointer(exploit_plan["causal_target_pointer"]) is True


def test_case_b_hallucinated_pointers_trigger_revision_and_succeed(
    incident_graph: EvidenceGraph,
) -> None:
    """Case B: Hallucinated RCA pointers trigger R=3 revision loop and repair ungrounded claims."""

    def initial_hallucinating_rca_llm(
        input_data: Dict[str, Any],
        graph: EvidenceGraph,
    ) -> Dict[str, Any]:
        """Mock LLM backend that initially emits hallucinated pointers in Slots 3 and 4."""
        return {
            "six_slot_chain": {
                "pre_attack_state": {
                    "slot_index": 1,
                    "slot_name": "pre_attack_state",
                    "description": "Pre-attack reserve state in ReentrantVault.",
                    "evidence_pointers": ["STATE:0xReentrantVault:0x00"],
                },
                "attacker_input": {
                    "slot_index": 2,
                    "slot_name": "attacker_input",
                    "description": "Attacker calls withdrawAll with malicious fallback.",
                    "evidence_pointers": ["CALL-1"],
                },
                "vulnerable_operation": {
                    "slot_index": 3,
                    "slot_name": "vulnerable_operation",
                    "description": "External call before shares update.",
                    "evidence_pointers": ["AST-HALLUCINATED-999"],  # Invalid pointer!
                },
                "state_invariant_breakdown": {
                    "slot_index": 4,
                    "slot_name": "state_invariant_breakdown",
                    "description": "Solvency invariant violated.",
                    "evidence_pointers": ["INV-HALLUCINATED-000"],  # Invalid pointer!
                },
                "asset_flow_impact": {
                    "slot_index": 5,
                    "slot_name": "asset_flow_impact",
                    "description": "10 ETH drained from ReentrantVault.",
                    "evidence_pointers": ["ASSET-ETH-1"],
                },
                "minimal_causal_chain": {
                    "slot_index": 6,
                    "slot_name": "minimal_causal_chain",
                    "description": "CALL-1 -> ReentrantVault:withdrawAll:3 -> ASSET-ETH-1",
                    "evidence_pointers": [
                        "CALL-1",
                        "ReentrantVault:withdrawAll:3",
                        "ASSET-ETH-1",
                    ],
                },
            }
        }

    revision_rounds_seen: List[int] = []

    def mock_revision_backend(
        claims: List[CausalClaim],
        round_idx: int,
        graph: EvidenceGraph,
    ) -> List[CausalClaim]:
        revision_rounds_seen.append(round_idx)
        revised: List[CausalClaim] = []
        for c in claims:
            copy_c = c.model_copy(deep=True)
            if copy_c.status == ClaimStatus.UNGROUNDED:
                assert len(copy_c.invalid_pointers) > 0
                if "VULNERABLE_OPERATION" in copy_c.claim_id:
                    copy_c.evidence_pointers = ["ReentrantVault:withdrawAll:3"]
                elif "STATE_INVARIANT_BREAKDOWN" in copy_c.claim_id:
                    copy_c.evidence_pointers = ["INV-SOLVENCY-VAULT"]
            revised.append(copy_c)
        return revised

    rca_agent = RCAAgent(
        llm_backend=initial_hallucinating_rca_llm,
        revision_backend=mock_revision_backend,
    )
    pipeline = JanusPipeline(rca_agent=rca_agent, max_revision_rounds=3)

    result = pipeline.run(incident_graph)

    assert result.status == GateVerdict.VERIFIED_FOR_EXPLOIT
    assert result.is_verified is True
    assert result.gate_verdict.rounds_used == 2
    assert revision_rounds_seen == [1]
    assert result.exploit_output is not None
    assert all(c.status == ClaimStatus.GROUNDED for c in result.verified_claims)


def test_case_c_persistent_invalid_pointers_abstain_inconclusive(
    incident_graph: EvidenceGraph,
) -> None:
    """Case C: Persistent invalid pointers across R=3 rounds result in INCONCLUSIVE abstention."""

    def persistent_bad_rca_llm(
        input_data: Dict[str, Any],
        graph: EvidenceGraph,
    ) -> Dict[str, Any]:
        return {
            "six_slot_chain": {
                "pre_attack_state": {
                    "slot_index": 1,
                    "slot_name": "pre_attack_state",
                    "description": "Valid state pointer.",
                    "evidence_pointers": ["STATE:0xReentrantVault:0x00"],
                },
                "attacker_input": {
                    "slot_index": 2,
                    "slot_name": "attacker_input",
                    "description": "Valid call pointer.",
                    "evidence_pointers": ["CALL-1"],
                },
                "vulnerable_operation": {
                    "slot_index": 3,
                    "slot_name": "vulnerable_operation",
                    "description": "Unresolvable hallucinated AST node.",
                    "evidence_pointers": ["AST-NON-EXISTENT-NODE"],
                },
                "state_invariant_breakdown": {
                    "slot_index": 4,
                    "slot_name": "state_invariant_breakdown",
                    "description": "Valid invariant pointer.",
                    "evidence_pointers": ["INV-SOLVENCY-VAULT"],
                },
                "asset_flow_impact": {
                    "slot_index": 5,
                    "slot_name": "asset_flow_impact",
                    "description": "Valid asset pointer.",
                    "evidence_pointers": ["ASSET-ETH-1"],
                },
                "minimal_causal_chain": {
                    "slot_index": 6,
                    "slot_name": "minimal_causal_chain",
                    "description": "Chain includes ungrounded pointer.",
                    "evidence_pointers": ["CALL-1", "AST-NON-EXISTENT-NODE"],
                },
            }
        }

    def stubborn_revision_backend(
        claims: List[CausalClaim],
        round_idx: int,
        graph: EvidenceGraph,
    ) -> List[CausalClaim]:
        # Keeps returning non-existent pointers across all R=3 rounds
        for c in claims:
            if c.status == ClaimStatus.UNGROUNDED:
                c.evidence_pointers = [f"HALLUCINATED-PTR-ROUND-{round_idx}"]
        return claims

    rca_agent = RCAAgent(
        llm_backend=persistent_bad_rca_llm,
        revision_backend=stubborn_revision_backend,
        auto_repair_pointers=False,
    )
    pipeline = JanusPipeline(rca_agent=rca_agent, max_revision_rounds=3)

    result = pipeline.run(incident_graph)

    assert result.status == GateVerdict.INCONCLUSIVE
    assert result.is_verified is False
    assert result.gate_verdict.verdict == GateDecision.INCONCLUSIVE
    assert result.gate_verdict.rounds_used == 3
    assert len(result.gate_verdict.ungrounded_claim_ids) == 2
    # Crucial: ExploitAgent must NOT be invoked when gate abstains with INCONCLUSIVE
    assert result.exploit_output is None
    assert result.verified_claims == []

