"""AST & Code Structure Extractor for JANUS-Evidence.

Implements Section 2 (Component 1: Program Analyzer) of the JANUS-Evidence
Master Project Plan (v1.2.0). Parses either raw Solidity source code or
Slither/Solc AST JSON into `CodeNode` instances with accurate 1-based line
ranges and canonical `statement_id` (`contract_name:function_name:stmt_idx`),
and wires `DEPENDS_ON` and `CALLS` edges into the `EvidenceGraph`.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from core.analyzer.graph_builder import CodeNode, EdgeType, EvidenceGraph

_CONTRACT_HEADER_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_FUNC_MOD_HEADER_RE = re.compile(
    r"\b(function\s+([A-Za-z_][A-Za-z0-9_]*)|modifier\s+([A-Za-z_][A-Za-z0-9_]*)|constructor\b|receive\s*\(\s*\)|fallback\s*\()"
)
_IDENTIFIER_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
_ASSIGNMENT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.\[\]]*)\s*(?:\+|-|\*|/)?=[^=]")
_INTERNAL_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_SOLIDITY_KEYWORDS: Set[str] = {
    "if",
    "else",
    "for",
    "while",
    "do",
    "return",
    "revert",
    "require",
    "assert",
    "emit",
    "new",
    "delete",
    "mapping",
    "uint",
    "uint256",
    "uint128",
    "uint64",
    "uint32",
    "uint8",
    "int",
    "int256",
    "bool",
    "address",
    "bytes",
    "bytes32",
    "string",
    "memory",
    "storage",
    "calldata",
    "public",
    "private",
    "internal",
    "external",
    "view",
    "pure",
    "payable",
    "virtual",
    "override",
    "constant",
    "immutable",
    "unchecked",
    "msg",
    "block",
    "tx",
    "abi",
    "this",
    "super",
    "true",
    "false",
    "call",
    "delegatecall",
    "staticcall",
    "transfer",
    "send",
}


class ASTVisitor:
    """Extracts `CodeNode` elements and structural/data-flow edges into an `EvidenceGraph`."""

    def __init__(self, evidence_graph: Optional[EvidenceGraph] = None) -> None:
        self.graph: EvidenceGraph = evidence_graph if evidence_graph is not None else EvidenceGraph()

    def parse(
        self,
        source_or_ast: Union[str, Dict[str, Any]],
        file_path: str = "Contract.sol",
    ) -> List[CodeNode]:
        """Dispatch parser for either raw Solidity source string or Slither/Solc AST JSON."""
        if isinstance(source_or_ast, dict):
            return self.parse_ast_json(source_or_ast, default_file_path=file_path)
        if isinstance(source_or_ast, str):
            return self.parse_solidity_source(source_or_ast, file_path=file_path)
        raise TypeError(
            f"Expected Solidity source (str) or AST JSON (dict), got {type(source_or_ast).__name__}."
        )

    def parse_solidity_source(
        self,
        contract_source: str,
        file_path: str = "Contract.sol",
    ) -> List[CodeNode]:
        """Parse Solidity source code into statement-level and function-level `CodeNode`s.

        Assigns canonical `statement_id` of the form `contract_name:function_name:stmt_idx`
        and wires intra-function `DEPENDS_ON` and inter-function `CALLS` edges.
        """
        lines = contract_source.splitlines()
        extracted_nodes: List[CodeNode] = []
        function_entry_nodes: Dict[Tuple[str, str], CodeNode] = {}
        function_stmt_nodes: Dict[Tuple[str, str], List[CodeNode]] = {}

        current_contract = "GlobalScope"
        contract_brace_depth = 0
        current_function: Optional[str] = None
        function_brace_depth = 0
        brace_depth = 0
        in_function_body = False
        pending_function: Optional[str] = None
        pending_modifiers: Dict[Tuple[str, str], List[str]] = {}
        stmt_counter: Dict[Tuple[str, str], int] = {}

        for idx, raw_line in enumerate(lines):
            line_no = idx + 1
            stripped = self._strip_comments(raw_line).strip()
            if not stripped:
                continue

            # Detect contract / library / interface declaration
            contract_match = _CONTRACT_HEADER_RE.search(stripped)
            if contract_match and current_function is None:
                current_contract = contract_match.group(1)
                contract_brace_depth = brace_depth

            # Detect function or modifier header
            func_match = _FUNC_MOD_HEADER_RE.search(stripped)
            if func_match and current_function is None and pending_function is None:
                if func_match.group(2):
                    fn_name = func_match.group(2)
                elif func_match.group(3):
                    fn_name = func_match.group(3)
                elif stripped.startswith("constructor"):
                    fn_name = "constructor"
                elif stripped.startswith("receive"):
                    fn_name = "receive"
                else:
                    fn_name = "fallback"

                pending_function = fn_name
                stmt_counter[(current_contract, fn_name)] = 0
                function_stmt_nodes[(current_contract, fn_name)] = []

                # Extract potential modifier invocations on header line
                header_tokens = _IDENTIFIER_RE.findall(stripped)
                mods = [
                    tok
                    for tok in header_tokens
                    if tok not in _SOLIDITY_KEYWORDS and tok != fn_name and tok != "function" and tok != "modifier"
                ]
                pending_modifiers[(current_contract, fn_name)] = mods

                # Create entry header CodeNode (stmt_idx = 0)
                stmt_id = f"{current_contract}:{fn_name}:0"
                ast_id = f"AST:{current_contract}:{fn_name}:0"
                header_node = CodeNode(
                    ast_id=ast_id,
                    file_path=file_path,
                    contract_name=current_contract,
                    function_name=fn_name,
                    statement_id=stmt_id,
                    source_code=stripped,
                    line_range=(line_no, line_no),
                )
                self.graph.add_node(header_node)
                extracted_nodes.append(header_node)
                function_entry_nodes[(current_contract, fn_name)] = header_node
                function_stmt_nodes[(current_contract, fn_name)].append(header_node)

            open_braces = stripped.count("{")
            close_braces = stripped.count("}")

            if pending_function is not None and open_braces > 0:
                current_function = pending_function
                function_brace_depth = brace_depth + 1
                in_function_body = True
                pending_function = None
                brace_depth += open_braces - close_braces
                if brace_depth < function_brace_depth:
                    current_function = None
                    in_function_body = False
                continue

            brace_depth += open_braces - close_braces

            if in_function_body and current_function is not None:
                if brace_depth < function_brace_depth:
                    current_function = None
                    in_function_body = False
                    continue

                # Skip pure closing braces or control-flow-only braces
                if stripped in {"{", "}", "};"}:
                    continue

                key = (current_contract, current_function)
                stmt_counter[key] += 1
                s_idx = stmt_counter[key]
                stmt_id = f"{current_contract}:{current_function}:{s_idx}"
                ast_id = f"AST:{current_contract}:{current_function}:{s_idx}"

                stmt_node = CodeNode(
                    ast_id=ast_id,
                    file_path=file_path,
                    contract_name=current_contract,
                    function_name=current_function,
                    statement_id=stmt_id,
                    source_code=stripped,
                    line_range=(line_no, line_no),
                )
                self.graph.add_node(stmt_node)
                extracted_nodes.append(stmt_node)
                function_stmt_nodes[key].append(stmt_node)

            if brace_depth <= contract_brace_depth and current_function is None and close_braces > 0:
                pass

        # Wire intra-function DEPENDS_ON and inter-function/modifier CALLS edges
        self._wire_code_dependencies(
            function_entry_nodes=function_entry_nodes,
            function_stmt_nodes=function_stmt_nodes,
            pending_modifiers=pending_modifiers,
        )
        return extracted_nodes

    def parse_ast_json(
        self,
        ast_data: Dict[str, Any],
        default_file_path: str = "Contract.sol",
    ) -> List[CodeNode]:
        """Parse Slither / Solc AST JSON dictionary into `CodeNode`s and wire edges.

        Supports both:
        1. Structured JANUS/Slither AST format (`contracts` -> `functions` -> `statements`)
        2. Standard Solc `SourceUnit` AST format (`nodes` with `ContractDefinition` / `FunctionDefinition`)
        """
        file_path = str(ast_data.get("file_path") or ast_data.get("absolutePath") or default_file_path)
        extracted_nodes: List[CodeNode] = []
        function_entry_nodes: Dict[Tuple[str, str], CodeNode] = {}
        function_stmt_nodes: Dict[Tuple[str, str], List[CodeNode]] = {}
        pending_modifiers: Dict[Tuple[str, str], List[str]] = {}

        # Format 1: Structured `contracts` list
        if "contracts" in ast_data and isinstance(ast_data["contracts"], list):
            for contract_obj in ast_data["contracts"]:
                c_name = str(contract_obj.get("name") or contract_obj.get("contract_name") or "Contract")
                for fn_obj in contract_obj.get("functions", []):
                    f_name = str(fn_obj.get("name") or fn_obj.get("function_name") or "fallback")
                    key = (c_name, f_name)
                    function_stmt_nodes[key] = []
                    pending_modifiers[key] = list(fn_obj.get("modifiers", []))

                    statements = fn_obj.get("statements", [])
                    for idx, stmt in enumerate(statements, start=1):
                        stmt_id = str(
                            stmt.get("statement_id") or f"{c_name}:{f_name}:{idx}"
                        )
                        ast_id = str(
                            stmt.get("ast_id") or f"AST:{c_name}:{f_name}:{idx}"
                        )
                        line_range_raw = stmt.get("line_range", [idx, idx])
                        line_range = (int(line_range_raw[0]), int(line_range_raw[1]))
                        code_node = CodeNode(
                            ast_id=ast_id,
                            file_path=str(stmt.get("file_path") or file_path),
                            contract_name=c_name,
                            function_name=f_name,
                            statement_id=stmt_id,
                            source_code=str(stmt.get("source_code") or stmt.get("code") or ""),
                            line_range=line_range,
                        )
                        self.graph.add_node(code_node)
                        extracted_nodes.append(code_node)
                        function_stmt_nodes[key].append(code_node)
                        if idx == 1:
                            function_entry_nodes[key] = code_node

                        # Explicit AST-level dependencies or calls if provided in JSON
                        for dep_id in stmt.get("depends_on", []):
                            if self.graph.has_pointer(dep_id):
                                dep_node = self.graph.get_node(dep_id)
                                if dep_node is not None:
                                    self.graph.add_edge(
                                        code_node.node_id,
                                        dep_node.node_id,
                                        EdgeType.DEPENDS_ON,
                                    )

        # Format 2: Solc SourceUnit `nodes` list
        elif "nodes" in ast_data and isinstance(ast_data["nodes"], list):
            for top_node in ast_data["nodes"]:
                if top_node.get("nodeType") == "ContractDefinition":
                    c_name = str(top_node.get("name", "Contract"))
                    for sub_node in top_node.get("nodes", []):
                        if sub_node.get("nodeType") in {"FunctionDefinition", "ModifierDefinition"}:
                            f_name = str(sub_node.get("name") or sub_node.get("kind") or "fallback")
                            key = (c_name, f_name)
                            function_stmt_nodes[key] = []
                            pending_modifiers[key] = [
                                m.get("modifierName", {}).get("name", "")
                                for m in sub_node.get("modifiers", [])
                                if isinstance(m, dict)
                            ]
                            body = sub_node.get("body") or {}
                            stmts = body.get("statements", [])
                            for idx, stmt in enumerate(stmts, start=1):
                                raw_id = stmt.get("id", idx)
                                ast_id = f"AST-{raw_id}" if not str(raw_id).startswith("AST") else str(raw_id)
                                stmt_id = str(stmt.get("statement_id") or f"{c_name}:{f_name}:{idx}")
                                line_range_raw = stmt.get("line_range", [idx, idx])
                                code_node = CodeNode(
                                    ast_id=ast_id,
                                    file_path=file_path,
                                    contract_name=c_name,
                                    function_name=f_name,
                                    statement_id=stmt_id,
                                    source_code=str(stmt.get("source_code") or stmt.get("nodeType") or "stmt"),
                                    line_range=(int(line_range_raw[0]), int(line_range_raw[1])),
                                )
                                self.graph.add_node(code_node)
                                extracted_nodes.append(code_node)
                                function_stmt_nodes[key].append(code_node)
                                if idx == 1:
                                    function_entry_nodes[key] = code_node

        self._wire_code_dependencies(
            function_entry_nodes=function_entry_nodes,
            function_stmt_nodes=function_stmt_nodes,
            pending_modifiers=pending_modifiers,
        )
        return extracted_nodes

    def _wire_code_dependencies(
        self,
        function_entry_nodes: Dict[Tuple[str, str], CodeNode],
        function_stmt_nodes: Dict[Tuple[str, str], List[CodeNode]],
        pending_modifiers: Dict[Tuple[str, str], List[str]],
    ) -> None:
        """Wire intra-function `DEPENDS_ON` and inter-function `CALLS` edges."""
        for (contract_name, fn_name), stmts in function_stmt_nodes.items():
            last_writer_by_var: Dict[str, CodeNode] = {}
            prev_node: Optional[CodeNode] = None

            # Wire modifier dependencies if modifier exists in same contract
            entry_node = function_entry_nodes.get((contract_name, fn_name))
            for mod_name in pending_modifiers.get((contract_name, fn_name), []):
                mod_target = function_entry_nodes.get((contract_name, mod_name))
                if entry_node is not None and mod_target is not None and entry_node.node_id != mod_target.node_id:
                    self.graph.add_edge(
                        entry_node.node_id,
                        mod_target.node_id,
                        EdgeType.DEPENDS_ON,
                        metadata={"reason": "modifier_guard"},
                    )

            for stmt in stmts:
                code = stmt.source_code
                written_vars = self._extract_written_vars(code)
                read_vars = self._extract_read_vars(code, written_vars)

                # Data-flow dependency: if stmt reads a variable written by an earlier stmt
                linked_data_dep = False
                for r_var in read_vars:
                    if r_var in last_writer_by_var:
                        writer = last_writer_by_var[r_var]
                        if writer.node_id != stmt.node_id:
                            self.graph.add_edge(
                                stmt.node_id,
                                writer.node_id,
                                EdgeType.DEPENDS_ON,
                                metadata={"variable": r_var, "type": "data_flow"},
                            )
                            linked_data_dep = True

                # Control-flow sequential dependency to preceding statement in the function
                if prev_node is not None and not linked_data_dep and prev_node.node_id != stmt.node_id:
                    self.graph.add_edge(
                        stmt.node_id,
                        prev_node.node_id,
                        EdgeType.DEPENDS_ON,
                        metadata={"type": "control_flow"},
                    )

                for w_var in written_vars:
                    last_writer_by_var[w_var] = stmt

                # Detect internal function calls within the same contract
                for called_fn in _INTERNAL_CALL_RE.findall(code):
                    if called_fn in _SOLIDITY_KEYWORDS or called_fn == fn_name:
                        continue
                    callee_entry = function_entry_nodes.get((contract_name, called_fn))
                    if callee_entry is not None and callee_entry.node_id != stmt.node_id:
                        self.graph.add_edge(
                            stmt.node_id,
                            callee_entry.node_id,
                            EdgeType.CALLS,
                            metadata={"callee_function": called_fn},
                        )

                prev_node = stmt

    @staticmethod
    def _strip_comments(line: str) -> str:
        comment_idx = line.find("//")
        if comment_idx != -1:
            return line[:comment_idx]
        return line

    @classmethod
    def _extract_written_vars(cls, code: str) -> Set[str]:
        written: Set[str] = set()
        for match in _ASSIGNMENT_RE.finditer(code):
            lhs = match.group(1).strip()
            base_var = lhs.split("[")[0].split(".")[0].strip()
            if base_var and base_var not in _SOLIDITY_KEYWORDS:
                written.add(base_var)
        return written

    @classmethod
    def _extract_read_vars(cls, code: str, written_vars: Set[str]) -> Set[str]:
        tokens = set(_IDENTIFIER_RE.findall(code))
        return {
            tok
            for tok in tokens
            if tok not in _SOLIDITY_KEYWORDS and not tok.isdigit() and tok not in written_vars
        }

