"""Unit tests for ASTVisitor, TraceParser, and build_evidence_graph in Step 1.4."""

from typing import Any, Dict

import pytest

from core.analyzer.ast_visitor import ASTVisitor
from core.analyzer.graph_builder import (
    EvidenceGraph,
    NodeType,
    build_evidence_graph,
)
from core.analyzer.trace_parser import ERC20_TRANSFER_TOPIC0, TraceParser

SAMPLE_SOLIDITY_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    uint256 public totalLiquidity;

    modifier nonZero(uint256 amount) {
        require(amount > 0, "Zero amount");
        _;
    }

    function _updateAccounting(uint256 delta) internal {
        totalLiquidity = totalLiquidity - delta;
    }

    function withdraw(uint256 amount) external nonZero(amount) {
        uint256 userBal = balances[msg.sender];
        require(userBal >= amount, "Insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = userBal - amount;
        _updateAccounting(amount);
    }
}
"""


@pytest.fixture
def mock_trace_data() -> Dict[str, Any]:
    """Return realistic mock EVM trace, state diff, and ERC-20 transfer logs."""
    return {
        "incident_id": "INC-REENTRANCY-001",
        "tx": {
            "tx_hash": "0x999888777666555444333222111000aaabbbcccdddeeefff0001112223334445",
            "block_number": 19500123,
            "from_addr": "0xAttackerEOA",
            "to_addr": "0xAttackerContract",
            "calldata": "0x2e1a7d4d0000000000000000000000000000000000000000000000000de0b6b3a7640000",
            "value": "0x0",
            "gas_used": 385000,
            "status": 1,
        },
        "call_trace": {
            "call_id": "CALL-ROOT",
            "type": "CALL",
            "from": "0xAttackerEOA",
            "to": "0xAttackerContract",
            "value": 0,
            "input": "0x2e1a7d4d0000000000000000",
            "calls": [
                {
                    "call_id": "CALL-VAULT-WITHDRAW",
                    "type": "CALL",
                    "from": "0xAttackerContract",
                    "to": "0xVault",
                    "value": 0,
                    "input": "0x2e1a7d4d0000000000000000",
                    "calls": [
                        {
                            "call_id": "CALL-ORACLE-STATIC",
                            "type": "STATICCALL",
                            "from": "0xVault",
                            "to": "0xOracle",
                            "value": 0,
                            "input": "0xfeaf968c",
                        },
                        {
                            "call_id": "CALL-CALLBACK",
                            "type": "CALL",
                            "from": "0xVault",
                            "to": "0xAttackerContract",
                            "value": 1000000000000000000,
                            "input": "0x",
                        },
                    ],
                }
            ],
        },
        "state_diffs": [
            {
                "state_id": "STATE:0xVault:0x01",
                "contract_address": "0xVault",
                "storage_slot": "0x01",
                "variable_name": "balances[0xAttackerContract]",
                "pre_val": "1000000000000000000",
                "post_val": "0",
                "block_number": 19500123,
            },
            {
                "state_id": "STATE:0xVault:0x02",
                "contract_address": "0xVault",
                "storage_slot": "0x02",
                "variable_name": "totalLiquidity",
                "pre_val": "50000000000000000000",
                "post_val": "1000000000000000000",
                "block_number": 19500123,
            },
        ],
        "asset_transfers": [
            {
                "asset_id": "ASSET-ETH-DRAIN-1",
                "token_address": "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
                "symbol": "ETH",
                "from_addr": "0xVault",
                "to_addr": "0xAttackerContract",
                "amount": 49000000000000000000,
                "flow_type": "TRANSFER",
                "call_id": "CALL-CALLBACK",
            }
        ],
        "logs": [
            {
                "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "symbol": "USDC",
                "asset_id": "ASSET-LOG-USDC-1",
                "topics": [
                    ERC20_TRANSFER_TOPIC0,
                    "0x00000000000000000000000000000000000000000000000000000000000vault",
                    "0x00000000000000000000000000000000000000000000000000000000attacker",
                ],
                "data": "0x0000000000000000000000000000000000000000000000000000000005f5e100",
            }
        ],
        "invariants": [
            {
                "invariant_id": "INV-VAULT-SOLVENCY",
                "invariant_type": "SOLVENCY",
                "expression": "address(this).balance >= totalLiquidity",
                "violation_status": True,
                "violated_by": "STATE:0xVault:0x02",
            }
        ],
    }


def test_ast_visitor_parses_solidity_source_and_wires_edges() -> None:
    """Verify ASTVisitor extracts functions, modifiers, statements, and DEPENDS_ON/CALLS edges."""
    visitor = ASTVisitor()
    nodes = visitor.parse_solidity_source(
        SAMPLE_SOLIDITY_SOURCE, file_path="contracts/VulnerableVault.sol"
    )
    graph = visitor.graph

    assert len(nodes) >= 9
    # Verify canonical statement_id pointers (contract_name:function_name:stmt_idx)
    assert graph.has_pointer("VulnerableVault:nonZero:0") is True
    assert graph.has_pointer("VulnerableVault:nonZero:1") is True
    assert graph.has_pointer("VulnerableVault:_updateAccounting:1") is True
    assert graph.has_pointer("VulnerableVault:withdraw:0") is True
    assert graph.has_pointer("VulnerableVault:withdraw:1") is True
    assert graph.has_pointer("VulnerableVault:withdraw:3") is True
    assert graph.has_pointer("VulnerableVault:withdraw:6") is True

    # Verify 1-based line_range accuracy
    ext_call_node = graph.get_node("VulnerableVault:withdraw:3")
    assert ext_call_node is not None
    assert "msg.sender.call{value: amount}" in ext_call_node.source_code  # type: ignore[union-attr]
    assert ext_call_node.line_range[0] == 20  # type: ignore[union-attr]

    # Verify modifier guard dependency: withdraw entry DEPENDS_ON nonZero entry
    assert graph.has_pointer(
        "AST:VulnerableVault:withdraw:0->DEPENDS_ON->AST:VulnerableVault:nonZero:0"
    ) is True

    # Verify data-flow dependency: balances[msg.sender] = userBal - amount DEPENDS_ON userBal declaration
    assert graph.has_pointer(
        "AST:VulnerableVault:withdraw:5->DEPENDS_ON->AST:VulnerableVault:withdraw:1"
    ) is True

    # Verify internal function call edge: stmt 6 calls _updateAccounting entry
    assert graph.has_pointer(
        "AST:VulnerableVault:withdraw:6->CALLS->AST:VulnerableVault:_updateAccounting:0"
    ) is True


def test_ast_visitor_parses_structured_ast_json() -> None:
    """Verify ASTVisitor supports structured Slither/Solc AST JSON input."""
    mock_ast_json = {
        "file_path": "contracts/LendingPool.sol",
        "contracts": [
            {
                "name": "LendingPool",
                "functions": [
                    {
                        "name": "borrow",
                        "modifiers": [],
                        "statements": [
                            {
                                "ast_id": "AST:LendingPool:borrow:1",
                                "statement_id": "LendingPool:borrow:1",
                                "source_code": "uint256 collateral = deposits[msg.sender];",
                                "line_range": [12, 12],
                            },
                            {
                                "ast_id": "AST:LendingPool:borrow:2",
                                "statement_id": "LendingPool:borrow:2",
                                "source_code": "require(collateral >= amount);",
                                "line_range": [13, 13],
                            },
                        ],
                    }
                ],
            }
        ],
    }

    visitor = ASTVisitor()
    nodes = visitor.parse(mock_ast_json)
    assert len(nodes) == 2
    assert visitor.graph.has_pointer("LendingPool:borrow:1") is True
    assert visitor.graph.has_pointer("LendingPool:borrow:2") is True
    assert visitor.graph.has_pointer(
        "AST:LendingPool:borrow:2->DEPENDS_ON->AST:LendingPool:borrow:1"
    ) is True


def test_trace_parser_extracts_tx_calls_states_assets_and_invariants(
    mock_trace_data: Dict[str, Any],
) -> None:
    """Verify TraceParser populates TxNode, CallNode, StateNode, AssetNode, and InvariantNode."""
    parser = TraceParser()
    graph = parser.parse(mock_trace_data)

    assert len(graph.get_nodes_by_type(NodeType.TX)) == 1
    assert len(graph.get_nodes_by_type(NodeType.CALL)) == 4
    assert len(graph.get_nodes_by_type(NodeType.STATE)) == 2
    assert len(graph.get_nodes_by_type(NodeType.ASSET)) == 2
    assert len(graph.get_nodes_by_type(NodeType.INVARIANT)) == 1

    # Verify call tree edges
    tx_hash = mock_trace_data["tx"]["tx_hash"]
    assert graph.has_pointer(f"{tx_hash}->CALLS->CALL-ROOT") is True
    assert graph.has_pointer("CALL-ROOT->CALLS->CALL-VAULT-WITHDRAW") is True
    assert graph.has_pointer("CALL-VAULT-WITHDRAW->CALLS->CALL-ORACLE-STATIC") is True
    assert graph.has_pointer("CALL-VAULT-WITHDRAW->CALLS->CALL-CALLBACK") is True

    # Verify state modification edges
    assert graph.has_pointer("CALL-VAULT-WITHDRAW->MODIFIES_STATE->STATE:0xVault:0x01") is True
    assert graph.has_pointer("CALL-VAULT-WITHDRAW->MODIFIES_STATE->STATE:0xVault:0x02") is True

    # Verify asset transfer edges and invariant violation edge
    assert graph.has_pointer("CALL-CALLBACK->TRANSFERS_ASSET->ASSET-ETH-DRAIN-1") is True
    assert graph.has_pointer("STATE:0xVault:0x02->VIOLATES->INV-VAULT-SOLVENCY") is True


def test_build_evidence_graph_end_to_end_integration(
    mock_trace_data: Dict[str, Any],
) -> None:
    """Verify high-level build_evidence_graph orchestrates AST + Trace and links CodeNode->StateNode."""
    graph: EvidenceGraph = build_evidence_graph(
        contract_source=SAMPLE_SOLIDITY_SOURCE,
        trace_data=mock_trace_data,
        file_path="contracts/VulnerableVault.sol",
    )

    assert graph.incident_id == "INC-REENTRANCY-001"

    # Both static statement slices and on-chain state slots resolve via has_pointer()
    assert graph.has_pointer("VulnerableVault:withdraw:5") is True
    assert graph.has_pointer("VulnerableVault:_updateAccounting:1") is True
    assert graph.has_pointer("STATE:0xVault:0x01") is True
    assert graph.has_pointer("STATE:0xVault:0x02") is True
    assert graph.has_pointer("ASSET-ETH-DRAIN-1") is True
    assert graph.has_pointer("ASSET-LOG-USDC-1") is True

    # Verify cross-layer link between static assignment and runtime StateNode
    assert graph.has_pointer(
        "AST:VulnerableVault:withdraw:5->MODIFIES_STATE->STATE:0xVault:0x01"
    ) is True
    assert graph.has_pointer(
        "AST:VulnerableVault:_updateAccounting:1->MODIFIES_STATE->STATE:0xVault:0x02"
    ) is True

