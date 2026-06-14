"""Call graph construction from binary analysis.

Builds CallGraph instances by extracting direct, indirect and PLT calls from a
binary. Cache-backed construction lives in call_graph_cache.py so this module
stays focused on graph building.
"""

from __future__ import annotations

import logging
from typing import Any

from r2morph.analysis.call_graph import CallEdge, CallGraph, CallNode, CallType
from r2morph.analysis.call_graph_entry_points import find_entry_points
from r2morph.analysis.call_graph_parsing import (
    determine_call_type,
    extract_call_target,
    is_tail_call,
)
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class CallGraphBuilder:
    """
    Builds call graphs from binary analysis.

    Extracts call relationships from disassembly and builds
    a directed graph representation.

    Usage:
        builder = CallGraphBuilder()
        cg = builder.build(binary)
    """

    def __init__(self, include_indirect: bool = True, include_plt: bool = True):
        """
        Initialize the call graph builder.

        Args:
            include_indirect: Whether to include indirect calls
            include_plt: Whether to include PLT stubs
        """
        self.include_indirect = include_indirect
        self.include_plt = include_plt
        self._known_indirect_targets: dict[int, list[int]] = {}

    def build(self, binary: Binary) -> CallGraph:
        """
        Build a call graph from a binary.

        Args:
            binary: The binary to analyze

        Returns:
            CallGraph instance
        """
        cg = CallGraph()

        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, run analysis first")

        functions = binary.get_functions()
        logger.info(f"Building call graph from {len(functions)} functions")

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            func_name = func.get("name", f"sub_{func_addr:x}")
            func_size = func.get("size", 0)

            call_type = determine_call_type(func_name)

            node = CallNode(
                address=func_addr,
                name=func_name,
                size=func_size,
                call_type=call_type,
            )
            cg.add_node(node)

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            self._extract_calls(binary, func_addr, cg)

        entry_points = find_entry_points(binary, cg)
        cg.entry_points = entry_points

        cg._detect_recursion()
        cg.find_strongly_connected_components()

        logger.info(f"Call graph built: {len(cg.nodes)} nodes, {len(cg.edges)} edges, {len(entry_points)} entry points")

        return cg

    def _extract_calls(self, binary: Binary, func_addr: int, cg: CallGraph) -> None:
        """Extract call instructions from a function."""
        try:
            disasm = binary.get_function_disasm(func_addr)
            if not disasm:
                return

            for insn in disasm:
                self._process_instruction(binary, func_addr, insn, cg)

        except Exception as e:
            logger.debug(f"Error extracting calls from 0x{func_addr:x}: {e}")

    def _determine_call_type(self, name: str, func: dict) -> CallType:
        """Compatibility wrapper for call type classification."""
        return determine_call_type(name)

    def _process_instruction(self, binary: Binary, func_addr: int, insn: dict, cg: CallGraph) -> None:
        """Process a single instruction for call extraction."""
        disasm = insn.get("disasm", "").lower()
        offset = insn.get("offset", 0)

        if not disasm.startswith("call") and not is_tail_call(disasm):
            return

        call_target = extract_call_target(disasm)
        if call_target is None:
            return

        call_type = CallType.DIRECT
        is_tail = is_tail_call(disasm)

        if isinstance(call_target, int) and call_target in cg.nodes:
            target_node = cg.nodes[call_target]
            if target_node.call_type == CallType.PLT:
                call_type = CallType.PLT
        elif isinstance(call_target, str) and call_target.startswith("0x"):
            call_type = CallType.DIRECT
        else:
            call_type = CallType.INDIRECT
            if not self.include_indirect:
                return

        if call_type == CallType.PLT and not self.include_plt:
            return

        if isinstance(call_target, int):
            if call_target not in cg.nodes:
                target_node = CallNode(
                    address=call_target,
                    name=f"sub_{call_target:x}",
                    call_type=call_type,
                )
                cg.add_node(target_node)

            edge = CallEdge(
                caller=func_addr,
                callee=call_target,
                call_type=call_type,
                call_site=offset,
                is_tail_call=is_tail,
            )
            cg.add_edge(edge)

    def _extract_call_target(self, disasm: str) -> int | str | None:
        """Compatibility wrapper for parsing call targets."""
        return extract_call_target(disasm)

    def _is_tail_call(self, disasm: str) -> bool:
        """Compatibility wrapper for tail-call detection."""
        return is_tail_call(disasm)

    def _find_entry_points(self, binary: Binary, cg: CallGraph) -> list[int]:
        """Find entry point functions."""
        return find_entry_points(binary, cg)

    def resolve_indirect_call(self, binary: Binary, call_site: int, context: dict[str, Any] | None = None) -> list[int]:
        """
        Attempt to resolve an indirect call to possible targets.

        Args:
            binary: The binary being analyzed
            call_site: Address of the call instruction
            context: Additional context (register values, etc.)

        Returns:
            List of possible target addresses
        """
        targets: list[int] = []

        if call_site in self._known_indirect_targets:
            return self._known_indirect_targets[call_site]

        if context and "possible_targets" in context:
            targets = context["possible_targets"]

        functions = binary.get_functions()
        func_starts = {f.get("offset", f.get("addr", 0)) for f in functions}

        for addr in targets:
            if addr in func_starts:
                if call_site not in self._known_indirect_targets:
                    self._known_indirect_targets[call_site] = []
                self._known_indirect_targets[call_site].append(addr)

        return self._known_indirect_targets.get(call_site, targets)


def build_call_graph(binary: Binary, include_indirect: bool = True, include_plt: bool = True) -> CallGraph:
    """
    Convenience function to build a call graph.

    Args:
        binary: The binary to analyze
        include_indirect: Whether to include indirect calls
        include_plt: Whether to include PLT stubs

    Returns:
        CallGraph instance
    """
    builder = CallGraphBuilder(include_indirect=include_indirect, include_plt=include_plt)
    return builder.build(binary)


def build_call_graph_cached(
    binary: Binary,
    cache: Any | None = None,
    include_indirect: bool = True,
    include_plt: bool = True,
) -> CallGraph:
    """Compatibility wrapper that delegates to call_graph_cache."""
    from r2morph.analysis.call_graph_cache import build_call_graph_cached as _build_call_graph_cached

    return _build_call_graph_cached(
        binary,
        cache=cache,
        include_indirect=include_indirect,
        include_plt=include_plt,
    )
