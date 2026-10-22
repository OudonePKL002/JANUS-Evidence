"""Unit tests for the formal Evidence Graph schema G = (N, E) in core/analyzer/graph_builder.py."""

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
    NodeType,
    StateNode,
    TxNode,
)


@pytest.fixture
def sample_evidence_graph() -> EvidenceGraph:
    """Construct a complete sample Evidence Graph containing all 6 node types and 5 edge types."""
    eg = EvidenceGraph(incident_id="INC-2026-001")

    tx_node = TxNode(
        tx_hash="0xabc123def456",
        block_number=18500000,
        from_addr="0xAttackerEOA",
        to_addr="0xExploitContract",
        calldata="0xdeadbeef",
        value=0,
        gas_used=450000,
        status=1,
    )

    call_node = CallNode(
        call_id="CALL-001",
        parent_call_id=None,
        caller="0xExploitContract",
        callee="0xVulnerableVault",
        value=0,
        function_selector="0x2e1a7d4d",
        call_type=CallType.CALL,
    )

    code_node = CodeNode(
        ast_id="AST-104",
        file_path="contracts/VulnerableVault.sol",
        contract_name="VulnerableVault",
        function_name="withdraw",
        statement_id="STMT-104-2",
        source_code="(bool success, ) = msg.sender.call{value: amount}(\"\");",
        line_range=(42, 42),
    )

    state_node = StateNode(
        state_id="STATE-SLOT-3",
        contract_address="0xVulnerableVault",
        storage_slot="0x0000000000000000000000000000000000000000000000000000000000000003",
        variable_name="userBalances[0xExploitContract]",
        pre_val="100000000000000000000",
        post_val="0",
        block_number=18500000,
    )

    asset_node = AssetNode(
        asset_id="ASSET-FLOW-1",
        token_address="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        symbol="WETH",
        from_addr="0xVulnerableVault",
        to_addr="0xExploitContract",
        amount=1000 * 10**18,
        flow_type="TRANSFER",
    )

    invariant_node = InvariantNode(
        invariant_id="INV-SOLVENCY-01",
        invariant_type=InvariantType.SOLVENCY,
        expression="totalAssets >= totalShares",
        violation_status=True,
    )

    # Add all 6 node types
    for node in (tx_node, call_node, code_node, state_node, asset_node, invariant_node):
        eg.add_node(node)

    # Add all 5 canonical edge types
    eg.add_edge("0xabc123def456", "CALL-001", EdgeType.CALLS)
    eg.add_edge("CALL-001", "AST-104", EdgeType.DEPENDS_ON)
    eg.add_edge("AST-104", "STATE-SLOT-3", EdgeType.MODIFIES_STATE)
    eg.add_edge("CALL-001", "ASSET-FLOW-1", EdgeType.TRANSFERS_ASSET)
    eg.add_edge("STATE-SLOT-3", "INV-SOLVENCY-01", EdgeType.VIOLATES)

    return eg


def test_all_six_node_types_and_five_edges_added(sample_evidence_graph: EvidenceGraph) -> None:
    """Verify all 6 node types and 5 edge types are stored and retrievable."""
    eg = sample_evidence_graph
    assert eg.num_nodes == 6
    assert eg.num_edges == 5

    assert len(eg.get_nodes_by_type(NodeType.TX)) == 1
    assert len(eg.get_nodes_by_type(NodeType.CALL)) == 1
    assert len(eg.get_nodes_by_type(NodeType.CODE)) == 1
    assert len(eg.get_nodes_by_type(NodeType.STATE)) == 1
    assert len(eg.get_nodes_by_type(NodeType.ASSET)) == 1
    assert len(eg.get_nodes_by_type(NodeType.INVARIANT)) == 1


def test_has_pointer_for_evidence_gate(sample_evidence_graph: EvidenceGraph) -> None:
    """Verify has_pointer() resolves primary node IDs, statement IDs, and edge IDs."""
    eg = sample_evidence_graph

    # Primary node pointers
    assert eg.has_pointer("0xabc123def456") is True
    assert eg.has_pointer("CALL-001") is True
    assert eg.has_pointer("AST-104") is True
    assert eg.has_pointer("STATE-SLOT-3") is True
    assert eg.has_pointer("ASSET-FLOW-1") is True
    assert eg.has_pointer("INV-SOLVENCY-01") is True

    # Secondary CodeNode statement_id pointer
    assert eg.has_pointer("STMT-104-2") is True
    assert eg.get_node("STMT-104-2") is not None
    assert eg.get_node("STMT-104-2").node_id == "AST-104"  # type: ignore[union-attr]

    # Canonical directed edge pointers
    assert eg.has_pointer("0xabc123def456->CALLS->CALL-001") is True
    assert eg.has_pointer("CALL-001->DEPENDS_ON->AST-104") is True
    assert eg.has_pointer("AST-104->MODIFIES_STATE->STATE-SLOT-3") is True
    assert eg.has_pointer("CALL-001->TRANSFERS_ASSET->ASSET-FLOW-1") is True
    assert eg.has_pointer("STATE-SLOT-3->VIOLATES->INV-SOLVENCY-01") is True

    # Hallucinated / non-existent pointers must return False
    assert eg.has_pointer("AST-999999") is False
    assert eg.has_pointer("CALL-001->VIOLATES->AST-104") is False
    assert eg.has_pointer("") is False


def test_validation_and_error_handling(sample_evidence_graph: EvidenceGraph) -> None:
    """Verify strict type checking and edge validation on invalid inputs."""
    eg = sample_evidence_graph

    with pytest.raises(TypeError):
        eg.add_node({"not": "a_valid_node"})  # type: ignore[arg-type]

    with pytest.raises(KeyError):
        eg.add_edge("NON_EXISTENT_SRC", "CALL-001", EdgeType.CALLS)

    with pytest.raises(KeyError):
        eg.add_edge("CALL-001", "NON_EXISTENT_DST", EdgeType.CALLS)

    with pytest.raises(ValueError):
        eg.add_edge("CALL-001", "AST-104", "INVALID_EDGE_RELATION")

    with pytest.raises(ValueError):
        CodeNode(
            ast_id="AST-ERR",
            file_path="contracts/Vault.sol",
            contract_name="Vault",
            function_name="bad",
            statement_id="STMT-ERR",
            source_code="revert();",
            line_range=(50, 10),  # start > end should fail
        )


def test_export_subgraph_and_serialization_roundtrip(sample_evidence_graph: EvidenceGraph) -> None:
    """Verify export_subgraph() and JSON/dict serialization round-trip."""
    eg = sample_evidence_graph

    sub = eg.export_subgraph(["CALL-001", "AST-104", "STATE-SLOT-3"])
    assert sub.num_nodes == 3
    assert sub.num_edges == 2
    assert sub.has_pointer("CALL-001->DEPENDS_ON->AST-104") is True
    assert sub.has_pointer("AST-104->MODIFIES_STATE->STATE-SLOT-3") is True
    assert sub.has_pointer("INV-SOLVENCY-01") is False

    # Round-trip serialization
    serialized = eg.to_dict()
    reconstructed = EvidenceGraph.from_dict(serialized)
    assert reconstructed.incident_id == "INC-2026-001"
    assert reconstructed.num_nodes == eg.num_nodes
    assert reconstructed.num_edges == eg.num_edges
    assert reconstructed.has_pointer("STATE-SLOT-3->VIOLATES->INV-SOLVENCY-01") is True
    assert len(reconstructed.to_json()) > 100

