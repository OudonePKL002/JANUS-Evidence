"""On-Chain Trace, Storage Diff, and Asset Flow Parser for JANUS-Evidence.

Implements Section 2 (Component 1: On-Chain Analyzer) of the JANUS-Evidence
Master Project Plan (v1.2.0). Parses EVM transaction receipts, `debug_traceTransaction`
callTracer / structLog traces, storage state diffs, and ERC-20 / native token
transfers into `TxNode`, `CallNode`, `StateNode`, `AssetNode`, and `InvariantNode`
objects, and wires `CALLS`, `MODIFIES_STATE`, `TRANSFERS_ASSET`, and `VIOLATES`
edges into the `EvidenceGraph`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from core.analyzer.graph_builder import (
    AssetNode,
    CallNode,
    CallType,
    EdgeType,
    EvidenceGraph,
    InvariantNode,
    InvariantType,
    StateNode,
    TxNode,
)

ERC20_TRANSFER_TOPIC0 = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)


class TraceParser:
    """Extracts on-chain execution trace, storage state diffs, and token flows into an `EvidenceGraph`."""

    def __init__(self, evidence_graph: Optional[EvidenceGraph] = None) -> None:
        self.graph: EvidenceGraph = evidence_graph if evidence_graph is not None else EvidenceGraph()

    def parse(self, trace_data: Dict[str, Any]) -> EvidenceGraph:
        """Parse a composite transaction trace and state diff payload into `self.graph`."""
        if not isinstance(trace_data, dict):
            raise TypeError(f"Expected trace_data dict, got {type(trace_data).__name__}.")

        tx_node = self._parse_tx_node(trace_data)
        call_nodes = self._parse_call_frames(trace_data, tx_node)
        state_nodes = self._parse_state_diffs(trace_data, tx_node, call_nodes)
        self._parse_asset_transfers(trace_data, tx_node, call_nodes)
        self._parse_invariants(trace_data, state_nodes)

        return self.graph

    def _parse_tx_node(self, trace_data: Dict[str, Any]) -> TxNode:
        """Extract root `TxNode` from receipt or top-level trace dictionary."""
        tx_raw = trace_data.get("tx") or trace_data.get("receipt") or trace_data

        tx_hash = str(
            tx_raw.get("tx_hash")
            or tx_raw.get("transactionHash")
            or tx_raw.get("hash")
            or "0x0000000000000000000000000000000000000000000000000000000000000000"
        )
        block_number = self._parse_int(
            tx_raw.get("block_number", tx_raw.get("blockNumber", trace_data.get("block_number", 0)))
        )
        from_addr = str(tx_raw.get("from_addr") or tx_raw.get("from") or "0x0")
        to_addr_raw = tx_raw.get("to_addr", tx_raw.get("to"))
        to_addr = str(to_addr_raw) if to_addr_raw is not None else None
        calldata = str(tx_raw.get("calldata") or tx_raw.get("input") or tx_raw.get("data") or "0x")
        value = self._parse_int(tx_raw.get("value", 0))
        gas_used = self._parse_int(tx_raw.get("gas_used", tx_raw.get("gasUsed", 0)))
        status = self._parse_int(tx_raw.get("status", 1))
        status = 1 if status != 0 else 0

        tx_node = TxNode(
            tx_hash=tx_hash,
            block_number=block_number,
            from_addr=from_addr,
            to_addr=to_addr,
            calldata=calldata,
            value=value,
            gas_used=gas_used,
            status=status,
        )
        self.graph.add_node(tx_node)
        return tx_node

    def _parse_call_frames(
        self,
        trace_data: Dict[str, Any],
        tx_node: TxNode,
    ) -> List[CallNode]:
        """Extract `CallNode` hierarchy from `call_trace`, `calls`, or `structLogs`."""
        extracted_calls: List[CallNode] = []
        counter = [0]

        def visit_frame(frame: Dict[str, Any], parent_call_id: Optional[str]) -> None:
            counter[0] += 1
            call_id = str(frame.get("call_id") or f"CALL-{counter[0]}")
            raw_type = str(frame.get("call_type") or frame.get("type") or "CALL").upper()
            try:
                call_type = CallType(raw_type)
            except ValueError:
                call_type = CallType.CALL

            caller = str(frame.get("caller") or frame.get("from") or tx_node.from_addr)
            callee = str(frame.get("callee") or frame.get("to") or tx_node.to_addr or "0x0")
            value = self._parse_int(frame.get("value", 0))

            selector = frame.get("function_selector")
            if not selector:
                inp = str(frame.get("input") or frame.get("calldata") or "0x")
                selector = inp[:10] if len(inp) >= 10 and inp.startswith("0x") else "fallback"

            call_node = CallNode(
                call_id=call_id,
                parent_call_id=parent_call_id,
                caller=caller,
                callee=callee,
                value=value,
                function_selector=str(selector),
                call_type=call_type,
            )
            self.graph.add_node(call_node)
            extracted_calls.append(call_node)

            if parent_call_id is None:
                self.graph.add_edge(tx_node.node_id, call_node.node_id, EdgeType.CALLS)
            elif self.graph.has_pointer(parent_call_id):
                self.graph.add_edge(parent_call_id, call_node.node_id, EdgeType.CALLS)

            for sub_frame in frame.get("calls", []):
                if isinstance(sub_frame, dict):
                    visit_frame(sub_frame, call_node.node_id)

        if "call_trace" in trace_data and isinstance(trace_data["call_trace"], dict):
            visit_frame(trace_data["call_trace"], None)
        elif "calls" in trace_data and isinstance(trace_data["calls"], list):
            for item in trace_data["calls"]:
                if isinstance(item, dict):
                    parent_id = item.get("parent_call_id")
                    visit_frame(item, str(parent_id) if parent_id else None)
        elif "structLogs" in trace_data and isinstance(trace_data["structLogs"], list):
            for step in trace_data["structLogs"]:
                op = str(step.get("op", "")).upper()
                if op in {"CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"}:
                    visit_frame(
                        {
                            "call_id": step.get("call_id"),
                            "type": op,
                            "from": step.get("caller") or tx_node.to_addr or tx_node.from_addr,
                            "to": step.get("callee") or "0xCallee",
                            "value": step.get("value", 0),
                            "function_selector": step.get("function_selector", "0x00000000"),
                        },
                        None,
                    )

        return extracted_calls

    def _parse_state_diffs(
        self,
        trace_data: Dict[str, Any],
        tx_node: TxNode,
        call_nodes: List[CallNode],
    ) -> List[StateNode]:
        """Extract `StateNode` storage transitions and wire `MODIFIES_STATE` edges."""
        extracted_states: List[StateNode] = []
        raw_diffs = (
            trace_data.get("state_diffs")
            or trace_data.get("storage_diffs")
            or trace_data.get("stateDiff")
            or []
        )

        # Build lookup of calls by callee address (lowercase) for automatic edge attribution
        calls_by_callee: Dict[str, List[CallNode]] = {}
        for c_node in call_nodes:
            calls_by_callee.setdefault(c_node.callee.lower(), []).append(c_node)

        if isinstance(raw_diffs, list):
            for idx, item in enumerate(raw_diffs, start=1):
                if not isinstance(item, dict):
                    continue
                contract_addr = str(item.get("contract_address") or item.get("address") or tx_node.to_addr or "0x0")
                slot = str(item.get("storage_slot") or item.get("slot") or f"0x{idx:02x}")
                state_id = str(item.get("state_id") or f"STATE:{contract_addr}:{slot}")
                var_name = str(item.get("variable_name") or item.get("variable") or f"slot_{slot}")
                pre_val = str(item.get("pre_val", item.get("pre", "0x0")))
                post_val = str(item.get("post_val", item.get("post", "0x0")))
                block_num = self._parse_int(item.get("block_number", tx_node.block_number))

                state_node = StateNode(
                    state_id=state_id,
                    contract_address=contract_addr,
                    storage_slot=slot,
                    variable_name=var_name,
                    pre_val=pre_val,
                    post_val=post_val,
                    block_number=block_num,
                )
                self.graph.add_node(state_node)
                extracted_states.append(state_node)

                # Wire MODIFIES_STATE from explicit source or matching CallNode / TxNode
                modifier_id = item.get("modified_by") or item.get("call_id") or item.get("ast_id")
                if modifier_id and self.graph.has_pointer(str(modifier_id)):
                    src_node = self.graph.get_node(str(modifier_id))
                    if src_node is not None:
                        self.graph.add_edge(src_node.node_id, state_node.node_id, EdgeType.MODIFIES_STATE)
                elif contract_addr.lower() in calls_by_callee:
                    for matching_call in calls_by_callee[contract_addr.lower()]:
                        self.graph.add_edge(
                            matching_call.node_id,
                            state_node.node_id,
                            EdgeType.MODIFIES_STATE,
                        )
                else:
                    self.graph.add_edge(tx_node.node_id, state_node.node_id, EdgeType.MODIFIES_STATE)

        elif isinstance(raw_diffs, dict):
            # Geth prestateTracer diffMode format: {address: {"storage": {slot: {"from": ..., "to": ...}}}}
            idx = 0
            for addr, account_diff in raw_diffs.items():
                if not isinstance(account_diff, dict):
                    continue
                storage_map = account_diff.get("storage", {})
                for slot, vals in storage_map.items():
                    idx += 1
                    if isinstance(vals, dict):
                        pre_val = str(vals.get("from", vals.get("pre", "0x0")))
                        post_val = str(vals.get("to", vals.get("post", "0x0")))
                    else:
                        pre_val, post_val = "0x0", str(vals)
                    state_id = f"STATE:{addr}:{slot}"
                    state_node = StateNode(
                        state_id=state_id,
                        contract_address=str(addr),
                        storage_slot=str(slot),
                        variable_name=f"slot_{slot}",
                        pre_val=pre_val,
                        post_val=post_val,
                        block_number=tx_node.block_number,
                    )
                    self.graph.add_node(state_node)
                    extracted_states.append(state_node)

                    if addr.lower() in calls_by_callee:
                        for matching_call in calls_by_callee[addr.lower()]:
                            self.graph.add_edge(
                                matching_call.node_id,
                                state_node.node_id,
                                EdgeType.MODIFIES_STATE,
                            )
                    else:
                        self.graph.add_edge(tx_node.node_id, state_node.node_id, EdgeType.MODIFIES_STATE)

        return extracted_states

    def _parse_asset_transfers(
        self,
        trace_data: Dict[str, Any],
        tx_node: TxNode,
        call_nodes: List[CallNode],
    ) -> List[AssetNode]:
        """Extract `AssetNode` records from `asset_transfers` or ERC-20 `Transfer` logs."""
        extracted_assets: List[AssetNode] = []
        raw_transfers = trace_data.get("asset_transfers") or []

        for idx, item in enumerate(raw_transfers, start=1):
            if not isinstance(item, dict):
                continue
            asset_id = str(item.get("asset_id") or f"ASSET-{idx}")
            token_addr = str(item.get("token_address") or item.get("token") or "0xETH")
            symbol = str(item.get("symbol") or "TOKEN")
            from_addr = str(item.get("from_addr") or item.get("from") or "0x0")
            to_addr = str(item.get("to_addr") or item.get("to") or "0x0")
            amount = self._parse_int(item.get("amount", item.get("value", 0)))
            flow_type = str(item.get("flow_type") or "TRANSFER")

            asset_node = AssetNode(
                asset_id=asset_id,
                token_address=token_addr,
                symbol=symbol,
                from_addr=from_addr,
                to_addr=to_addr,
                amount=amount,
                flow_type=flow_type,
            )
            self.graph.add_node(asset_node)
            extracted_assets.append(asset_node)

            source_ptr = item.get("call_id") or item.get("triggered_by")
            if source_ptr and self.graph.has_pointer(str(source_ptr)):
                src_node = self.graph.get_node(str(source_ptr))
                if src_node is not None:
                    self.graph.add_edge(src_node.node_id, asset_node.node_id, EdgeType.TRANSFERS_ASSET)
            elif call_nodes:
                self.graph.add_edge(call_nodes[-1].node_id, asset_node.node_id, EdgeType.TRANSFERS_ASSET)
            else:
                self.graph.add_edge(tx_node.node_id, asset_node.node_id, EdgeType.TRANSFERS_ASSET)

        # Also parse raw EVM receipt logs for ERC-20 Transfer(address,address,uint256)
        raw_logs = trace_data.get("logs") or (trace_data.get("receipt", {}) or {}).get("logs") or []
        for log_idx, log_entry in enumerate(raw_logs, start=len(extracted_assets) + 1):
            if not isinstance(log_entry, dict):
                continue
            topics = [str(t).lower() for t in log_entry.get("topics", [])]
            if len(topics) >= 3 and topics[0] == ERC20_TRANSFER_TOPIC0:
                from_addr = "0x" + topics[1][-40:]
                to_addr = "0x" + topics[2][-40:]
                amount = self._parse_int(log_entry.get("data", "0x0"))
                token_addr = str(log_entry.get("address") or "0xToken")
                symbol = str(log_entry.get("symbol") or "ERC20")
                asset_id = str(log_entry.get("asset_id") or f"ASSET-LOG-{log_idx}")

                asset_node = AssetNode(
                    asset_id=asset_id,
                    token_address=token_addr,
                    symbol=symbol,
                    from_addr=from_addr,
                    to_addr=to_addr,
                    amount=amount,
                    flow_type="TRANSFER",
                )
                self.graph.add_node(asset_node)
                extracted_assets.append(asset_node)

                if call_nodes:
                    self.graph.add_edge(call_nodes[0].node_id, asset_node.node_id, EdgeType.TRANSFERS_ASSET)
                else:
                    self.graph.add_edge(tx_node.node_id, asset_node.node_id, EdgeType.TRANSFERS_ASSET)

        return extracted_assets

    def _parse_invariants(
        self,
        trace_data: Dict[str, Any],
        state_nodes: List[StateNode],
    ) -> List[InvariantNode]:
        """Extract optional `InvariantNode` definitions and wire `VIOLATES` edges."""
        extracted_invariants: List[InvariantNode] = []
        raw_invariants = trace_data.get("invariants") or []

        for idx, item in enumerate(raw_invariants, start=1):
            if not isinstance(item, dict):
                continue
            inv_id = str(item.get("invariant_id") or f"INV-{idx}")
            raw_type = str(item.get("invariant_type") or "CUSTOM").upper()
            try:
                inv_type = InvariantType(raw_type)
            except ValueError:
                inv_type = InvariantType.CUSTOM

            expr = str(item.get("expression") or "true")
            violated = bool(item.get("violation_status", False))

            inv_node = InvariantNode(
                invariant_id=inv_id,
                invariant_type=inv_type,
                expression=expr,
                violation_status=violated,
            )
            self.graph.add_node(inv_node)
            extracted_invariants.append(inv_node)

            if violated:
                violated_by = item.get("violated_by")
                if violated_by and self.graph.has_pointer(str(violated_by)):
                    v_node = self.graph.get_node(str(violated_by))
                    if v_node is not None:
                        self.graph.add_edge(v_node.node_id, inv_node.node_id, EdgeType.VIOLATES)
                elif state_nodes:
                    self.graph.add_edge(state_nodes[-1].node_id, inv_node.node_id, EdgeType.VIOLATES)

        return extracted_invariants

    @staticmethod
    def _parse_int(value: Union[int, str, None]) -> int:
        if value is None:
            return 0
        if isinstance(value, int):
            return value
        val_str = str(value).strip()
        if not val_str:
            return 0
        if val_str.startswith(("0x", "0X")):
            return int(val_str, 16) if len(val_str) > 2 else 0
        return int(val_str)

