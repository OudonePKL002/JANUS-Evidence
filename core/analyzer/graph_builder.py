"""Formal Evidence Graph Schema G = (N, E) and Container Implementation.

Implements Section 2.1 of the JANUS-Evidence Master Project Plan (v1.2.0).
Every agent claim in JANUS-Evidence must resolve to explicit node and edge
identifiers in the Evidence Graph G = (N, E).
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field, field_validator


class NodeType(str, Enum):
    """Canonical node types N in the Evidence Graph G = (N, E)."""

    CODE = "CodeNode"
    STATE = "StateNode"
    TX = "TxNode"
    CALL = "CallNode"
    ASSET = "AssetNode"
    INVARIANT = "InvariantNode"


class EdgeType(str, Enum):
    """Canonical directed edge relations E in the Evidence Graph G = (N, E)."""

    DEPENDS_ON = "DEPENDS_ON"
    CALLS = "CALLS"
    MODIFIES_STATE = "MODIFIES_STATE"
    TRANSFERS_ASSET = "TRANSFERS_ASSET"
    VIOLATES = "VIOLATES"


class CallType(str, Enum):
    """Supported EVM internal/external call opcodes."""

    CALL = "CALL"
    DELEGATECALL = "DELEGATECALL"
    STATICCALL = "STATICCALL"
    CALLCODE = "CALLCODE"
    CREATE = "CREATE"
    CREATE2 = "CREATE2"


class InvariantType(str, Enum):
    """Standard DeFi and smart contract security invariant classifications."""

    SOLVENCY = "SOLVENCY"
    BALANCE_PRESERVATION = "BALANCE_PRESERVATION"
    CONSTANT_PRODUCT = "CONSTANT_PRODUCT"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    REENTRANCY_GUARD = "REENTRANCY_GUARD"
    ORACLE_FRESHNESS = "ORACLE_FRESHNESS"
    COLLATERAL_RATIO = "COLLATERAL_RATIO"
    CUSTOM = "CUSTOM"


class BaseEvidenceNode(BaseModel):
    """Abstract base model for all nodes in the Evidence Graph."""

    model_config = ConfigDict(extra="forbid", frozen=False, validate_assignment=True)

    node_type: NodeType

    @property
    def node_id(self) -> str:
        """Return the unique primary pointer ID of the node."""
        raise NotImplementedError("Subclasses must implement node_id.")


class CodeNode(BaseEvidenceNode):
    """Represents a static AST/CFG/DFG code element in a smart contract."""

    node_type: NodeType = Field(default=NodeType.CODE, frozen=True)
    ast_id: str = Field(..., min_length=1, description="Unique AST node identifier")
    file_path: str = Field(..., min_length=1, description="Relative path to contract source file")
    contract_name: str = Field(..., min_length=1, description="Enclosing contract or library name")
    function_name: str = Field(..., min_length=1, description="Enclosing function or modifier name")
    statement_id: str = Field(..., min_length=1, description="Statement-level slice identifier")
    source_code: str = Field(..., description="Raw Solidity source snippet")
    line_range: Tuple[int, int] = Field(..., description="1-based inclusive (start_line, end_line)")

    @field_validator("line_range")
    @classmethod
    def validate_line_range(cls, v: Tuple[int, int]) -> Tuple[int, int]:
        start, end = v
        if start < 1 or end < start:
            raise ValueError(f"Invalid line_range ({start}, {end}): must satisfy 1 <= start <= end.")
        return v

    @property
    def node_id(self) -> str:
        return self.ast_id


class StateNode(BaseEvidenceNode):
    """Represents an on-chain storage slot state transition across a block/tx."""

    node_type: NodeType = Field(default=NodeType.STATE, frozen=True)
    state_id: str = Field(..., min_length=1, description="Unique state diff identifier")
    contract_address: str = Field(..., min_length=1, description="Contract address owning the storage slot")
    storage_slot: str = Field(..., min_length=1, description="Hex storage slot key")
    variable_name: str = Field(..., description="Resolved Solidity state variable name")
    pre_val: str = Field(..., description="Storage value prior to execution")
    post_val: str = Field(..., description="Storage value after execution")
    block_number: int = Field(..., ge=0, description="Block number of state observation")

    @property
    def node_id(self) -> str:
        return self.state_id


class TxNode(BaseEvidenceNode):
    """Represents a top-level blockchain transaction in an exploit or trace."""

    node_type: NodeType = Field(default=NodeType.TX, frozen=True)
    tx_hash: str = Field(..., min_length=1, description="Transaction hash (0x...)")
    block_number: int = Field(..., ge=0, description="Block number in which the tx was mined")
    from_addr: str = Field(..., min_length=1, description="Sender EOA or contract address")
    to_addr: Optional[str] = Field(default=None, description="Recipient address (None for contract creation)")
    calldata: str = Field(default="0x", description="Hex-encoded transaction input payload")
    value: int = Field(default=0, ge=0, description="Native wei transferred with transaction")
    gas_used: int = Field(default=0, ge=0, description="Total gas consumed by execution")
    status: int = Field(..., ge=0, le=1, description="EVM execution status (1=success, 0=revert)")

    @property
    def node_id(self) -> str:
        return self.tx_hash


class CallNode(BaseEvidenceNode):
    """Represents an internal or external EVM message call frame within a transaction trace."""

    node_type: NodeType = Field(default=NodeType.CALL, frozen=True)
    call_id: str = Field(..., min_length=1, description="Unique call frame identifier")
    parent_call_id: Optional[str] = Field(
        default=None, description="Parent call frame ID (None for root call)"
    )
    caller: str = Field(..., min_length=1, description="Caller address (msg.sender)")
    callee: str = Field(..., min_length=1, description="Target contract address")
    value: int = Field(default=0, ge=0, description="Wei value passed in call frame")
    function_selector: str = Field(..., description="4-byte function selector (e.g., 0xa9059cbb) or fallback")
    call_type: CallType = Field(..., description="EVM call opcode type (CALL, DELEGATECALL, STATICCALL)")

    @property
    def node_id(self) -> str:
        return self.call_id


class AssetNode(BaseEvidenceNode):
    """Represents an ERC-20/ERC-721/native asset transfer or balance change event."""

    node_type: NodeType = Field(default=NodeType.ASSET, frozen=True)
    asset_id: str = Field(..., min_length=1, description="Unique asset flow identifier")
    token_address: str = Field(..., min_length=1, description="Token contract address or native ETH sentinel")
    symbol: str = Field(..., min_length=1, description="Token ticker symbol (e.g., WETH, USDC)")
    from_addr: str = Field(..., min_length=1, description="Source address of asset transfer")
    to_addr: str = Field(..., min_length=1, description="Destination address of asset transfer")
    amount: int = Field(..., ge=0, description="Raw token amount in smallest unit (wei/decimals)")
    flow_type: str = Field(..., min_length=1, description="Transfer classification (e.g., TRANSFER, MINT, BURN, SWAP)")

    @property
    def node_id(self) -> str:
        return self.asset_id


class InvariantNode(BaseEvidenceNode):
    """Represents a formal protocol or security invariant evaluated over state/asset nodes."""

    node_type: NodeType = Field(default=NodeType.INVARIANT, frozen=True)
    invariant_id: str = Field(..., min_length=1, description="Unique invariant identifier")
    invariant_type: InvariantType = Field(
        ..., description="Category of security invariant (SOLVENCY, BALANCE_PRESERVATION, CONSTANT_PRODUCT, etc.)"
    )
    expression: str = Field(..., min_length=1, description="Formal mathematical or symbolic invariant predicate")
    violation_status: bool = Field(..., description="True if the invariant was violated during execution")

    @property
    def node_id(self) -> str:
        return self.invariant_id


EvidenceNode = Union[CodeNode, StateNode, TxNode, CallNode, AssetNode, InvariantNode]

NODE_TYPE_MAP: Dict[str, type[BaseEvidenceNode]] = {
    NodeType.CODE.value: CodeNode,
    NodeType.STATE.value: StateNode,
    NodeType.TX.value: TxNode,
    NodeType.CALL.value: CallNode,
    NodeType.ASSET.value: AssetNode,
    NodeType.INVARIANT.value: InvariantNode,
}


class EvidenceEdge(BaseModel):
    """Typed directed edge E connecting two EvidenceNodes in G = (N, E)."""

    model_config = ConfigDict(extra="forbid", frozen=False, validate_assignment=True)

    source_id: str = Field(..., min_length=1, description="Origin node_id")
    target_id: str = Field(..., min_length=1, description="Destination node_id")
    edge_type: EdgeType = Field(..., description="Directed causal/structural relationship type")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Optional edge attributes")

    @property
    def edge_id(self) -> str:
        return f"{self.source_id}->{self.edge_type.value}->{self.target_id}"


class EvidenceGraph:
    """Structured container wrapping a networkx.DiGraph for the Evidence Graph G = (N, E).

    Enforces schema validation for all 6 node types and 5 edge types, and provides
    pointer lookup (`has_pointer`) required by the JANUS Evidence Gate.
    """

    def __init__(self, incident_id: Optional[str] = None) -> None:
        self.incident_id: Optional[str] = incident_id
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: Dict[str, EvidenceNode] = {}
        self._secondary_pointers: Dict[str, str] = {}

    @property
    def graph(self) -> nx.DiGraph:
        """Return the underlying networkx.DiGraph instance."""
        return self._graph

    @property
    def num_nodes(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def num_edges(self) -> int:
        return self._graph.number_of_edges()

    def add_node(self, node: EvidenceNode) -> str:
        """Add a typed EvidenceNode to G = (N, E) with strict type validation.

        Returns the canonical node_id.
        """
        if not isinstance(
            node, (CodeNode, StateNode, TxNode, CallNode, AssetNode, InvariantNode)
        ):
            raise TypeError(
                f"Expected a valid EvidenceNode instance, got {type(node).__name__}."
            )

        nid = node.node_id
        self._nodes[nid] = node
        self._graph.add_node(nid, **node.model_dump(mode="json"))

        # Register statement_id as a secondary valid pointer for CodeNode
        if isinstance(node, CodeNode):
            self._secondary_pointers[node.statement_id] = nid

        return nid

    def get_node(self, target_id: str) -> Optional[EvidenceNode]:
        """Retrieve a typed EvidenceNode by its primary node_id or secondary statement_id."""
        if target_id in self._nodes:
            return self._nodes[target_id]
        resolved_id = self._secondary_pointers.get(target_id)
        if resolved_id is not None:
            return self._nodes.get(resolved_id)
        return None

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: Union[EdgeType, str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvidenceEdge:
        """Add a validated directed relationship between two existing nodes in G = (N, E)."""
        if source_id not in self._nodes:
            raise KeyError(f"Source node '{source_id}' does not exist in EvidenceGraph.")
        if target_id not in self._nodes:
            raise KeyError(f"Target node '{target_id}' does not exist in EvidenceGraph.")

        if isinstance(edge_type, str) and not isinstance(edge_type, EdgeType):
            try:
                resolved_type = EdgeType(edge_type)
            except ValueError as exc:
                valid = [e.value for e in EdgeType]
                raise ValueError(
                    f"Invalid edge_type '{edge_type}'. Must be one of {valid}."
                ) from exc
        elif isinstance(edge_type, EdgeType):
            resolved_type = edge_type
        else:
            raise TypeError(f"Invalid edge_type type: {type(edge_type).__name__}")

        edge = EvidenceEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=resolved_type,
            metadata=metadata or {},
        )

        # Support multiple relation types between the same node pair on DiGraph
        existing_edge_data = self._graph.get_edge_data(source_id, target_id)
        relations: List[str] = []
        if existing_edge_data and "relations" in existing_edge_data:
            relations = list(existing_edge_data["relations"])
        if resolved_type.value not in relations:
            relations.append(resolved_type.value)

        self._graph.add_edge(
            source_id,
            target_id,
            edge_type=resolved_type.value,
            relations=relations,
            edge_id=edge.edge_id,
            metadata=edge.metadata,
        )
        return edge

    def has_pointer(self, target_id: str) -> bool:
        """Check whether `target_id` resolves to an existing node, statement_id, or edge pointer in G.

        Used by the Evidence Gate to verify that every LLM claim references valid evidence.
        """
        if not target_id or not isinstance(target_id, str):
            return False

        # 1. Direct primary node ID match
        if target_id in self._nodes:
            return True

        # 2. Secondary pointer match (e.g., CodeNode.statement_id)
        if target_id in self._secondary_pointers:
            return True

        # 3. Canonical edge pointer match: "src->EDGE_TYPE->dst"
        if "->" in target_id:
            parts = target_id.split("->")
            if len(parts) == 3:
                src, rel, dst = parts
                if self._graph.has_edge(src, dst):
                    edge_data = self._graph.get_edge_data(src, dst) or {}
                    relations = edge_data.get("relations", [edge_data.get("edge_type")])
                    if rel in relations:
                        return True

        return False

    def get_nodes_by_type(self, node_type: Union[NodeType, str]) -> List[EvidenceNode]:
        """Return all nodes matching the given NodeType."""
        resolved_type = NodeType(node_type) if isinstance(node_type, str) else node_type
        return [n for n in self._nodes.values() if n.node_type == resolved_type]

    def export_subgraph(self, node_ids: Iterable[str]) -> "EvidenceGraph":
        """Export an induced EvidenceGraph containing only the specified `node_ids` and interconnecting edges."""
        sub = EvidenceGraph(incident_id=self.incident_id)
        resolved_ids: List[str] = []

        for raw_id in node_ids:
            node = self.get_node(raw_id)
            if node is None:
                raise KeyError(f"Cannot export unknown node pointer '{raw_id}'.")
            sub.add_node(node)
            resolved_ids.append(node.node_id)

        resolved_set = set(resolved_ids)
        for u, v, data in self._graph.edges(data=True):
            if u in resolved_set and v in resolved_set:
                relations = data.get("relations", [data.get("edge_type")])
                for rel in relations:
                    if rel:
                        sub.add_edge(u, v, EdgeType(rel), metadata=data.get("metadata"))

        return sub

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the complete EvidenceGraph to a JSON-compatible dictionary."""
        edges_list: List[Dict[str, Any]] = []
        for u, v, data in self._graph.edges(data=True):
            relations = data.get("relations", [data.get("edge_type")])
            for rel in relations:
                if rel:
                    edges_list.append(
                        {
                            "source_id": u,
                            "target_id": v,
                            "edge_type": rel,
                            "metadata": data.get("metadata", {}),
                        }
                    )

        return {
            "incident_id": self.incident_id,
            "nodes": [node.model_dump(mode="json") for node in self._nodes.values()],
            "edges": edges_list,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize the EvidenceGraph to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "EvidenceGraph":
        """Reconstruct an EvidenceGraph instance from its dictionary representation."""
        instance = cls(incident_id=payload.get("incident_id"))
        for raw_node in payload.get("nodes", []):
            ntype = raw_node.get("node_type")
            model_cls = NODE_TYPE_MAP.get(ntype)
            if model_cls is None:
                raise ValueError(f"Unknown node_type '{ntype}' in serialized payload.")
            node_obj = model_cls.model_validate(raw_node)
            instance.add_node(node_obj)  # type: ignore[arg-type]

        for raw_edge in payload.get("edges", []):
            instance.add_edge(
                source_id=raw_edge["source_id"],
                target_id=raw_edge["target_id"],
                edge_type=EdgeType(raw_edge["edge_type"]),
                metadata=raw_edge.get("metadata", {}),
            )
        return instance

