"""Interprocedural memory flow analysis helpers."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class InterproceduralDataFlowAnalyzer:
    """
    Performs interprocedural data flow analysis.

    Tracks data flow across function boundaries using:
    - Function summaries
    - Call graph propagation
    - Context sensitivity
    """

    def __init__(self) -> None:
        self._function_summaries: dict[int, dict[str, Any]] = {}
        self._call_graph: dict[int, list[int]] = {}

    def analyze_program(
        self,
        functions: list[dict[str, Any]],
        call_graph: dict[int, list[int]],
    ) -> dict[str, Any]:
        """
        Perform interprocedural analysis on a program.

        Args:
            functions: List of function dictionaries with instructions
            call_graph: Dict mapping function address to list of call targets

        Returns:
            Dictionary with analysis results
        """
        self._call_graph = call_graph
        self._function_summaries.clear()

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            instructions = func.get("instructions", func.get("disasm", []))

            summary = self._analyze_function_summary(func_addr, instructions)
            self._function_summaries[func_addr] = summary

        propagated = self._propagate_through_call_graph()

        return {
            "function_summaries": {f"0x{addr:x}": summary for addr, summary in self._function_summaries.items()},
            "call_graph": {
                f"0x{caller:x}": [f"0x{callee:x}" for callee in callees] for caller, callees in self._call_graph.items()
            },
            "propagated_values": propagated,
        }

    def _analyze_function_summary(
        self,
        func_addr: int,
        instructions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Compute a function summary for interprocedural analysis.

        A summary captures:
        - Input/output parameters
        - Side effects
        - Return values
        - Modified globals
        """
        summary: dict[str, Any] = {
            "address": f"0x{func_addr:x}",
            "parameters": [],
            "return_values": [],
            "side_effects": [],
            "modified_registers": set(),
            "read_globals": set(),
            "written_globals": set(),
        }

        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            addr = insn.get("offset", 0)
            self._record_instruction_effects(summary, disasm, addr)

        summary["modified_registers"] = list(summary["modified_registers"])
        summary["read_globals"] = list(summary["read_globals"])
        summary["written_globals"] = list(summary["written_globals"])

        return summary

    @staticmethod
    def _record_instruction_effects(summary: dict[str, Any], disasm: str, addr: int) -> None:
        """Record the side effects of a single instruction into a summary."""
        if "mov" in disasm or "ldr" in disasm:
            match = re.search(r"(mov|ldr)\s+(\w+),", disasm)
            if match:
                summary["modified_registers"].add(match.group(2))

        if "push" in disasm or "pop" in disasm:
            match = re.search(r"(push|pop)\s+(\w+)", disasm)
            if match:
                summary["modified_registers"].add(match.group(2))

        if "call" in disasm or "bl" in disasm:
            summary["side_effects"].append(
                {
                    "type": "call",
                    "address": f"0x{addr:x}",
                    "instruction": disasm,
                }
            )

        if "ret" in disasm or "bx lr" in disasm:
            match = re.search(r"mov\s+(\w+),", disasm)
            if match:
                summary["return_values"].append(
                    {
                        "register": match.group(1),
                        "type": "return",
                    }
                )

    def _propagate_through_call_graph(self) -> dict[str, Any]:
        """Propagate data flow information through the call graph."""
        propagated: dict[str, Any] = {
            "parameter_bindings": {},
            "value_flow": {},
        }

        visited: set[int] = set()

        for func_addr in self._function_summaries:
            self._propagate_from_function(func_addr, visited, propagated)

        return propagated

    def _propagate_from_function(
        self,
        func_addr: int,
        visited: set[int],
        propagated: dict[str, Any],
    ) -> None:
        """Propagate data flow from a function."""
        if func_addr in visited:
            return

        visited.add(func_addr)

        self._function_summaries.get(func_addr, {})
        callees = self._call_graph.get(func_addr, [])

        for callee_addr in callees:
            callee_summary = self._function_summaries.get(callee_addr, {})

            for param in callee_summary.get("parameters", []):
                key = f"0x{func_addr:x}:0x{callee_addr:x}:{param.get('name', 'unknown')}"
                propagated["parameter_bindings"][key] = {
                    "caller": f"0x{func_addr:x}",
                    "callee": f"0x{callee_addr:x}",
                    "parameter": param,
                }

            for ret_val in callee_summary.get("return_values", []):
                key = f"0x{callee_addr:x}:return:{ret_val.get('register', 'unknown')}"
                propagated["value_flow"][key] = {
                    "function": f"0x{callee_addr:x}",
                    "return_value": ret_val,
                    "callers": [f"0x{func_addr:x}"],
                }
