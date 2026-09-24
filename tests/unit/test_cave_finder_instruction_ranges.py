"""Regression tests for cave validation across scoped mutation analysis."""

from __future__ import annotations

from typing import Any

from r2morph.relocations.cave_finder import CaveFinder
from tests.utils.assertions import expect

_SCOPED_FUNCTION_ADDRESS = 0x1000
_UNSCOPED_FUNCTION_ADDRESS = 0x2000


class _AnalysisApi:
    def cmdj(self, command: str) -> list[dict[str, int]]:
        expect(command == "aflj")
        return [{"offset": _SCOPED_FUNCTION_ADDRESS}, {"offset": _UNSCOPED_FUNCTION_ADDRESS}]


class _ScopedBinary:
    r2 = _AnalysisApi()

    def get_functions(self) -> list[dict[str, int]]:
        return [{"offset": _SCOPED_FUNCTION_ADDRESS}]

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        if address == _SCOPED_FUNCTION_ADDRESS:
            return [
                {"addr": _SCOPED_FUNCTION_ADDRESS, "size": 1, "disasm": "nop"},
                {"addr": 0x1001, "size": 8, "disasm": "nop dword ptr [rax + rax]"},
            ]
        return [{"addr": _UNSCOPED_FUNCTION_ADDRESS, "size": 5, "disasm": "push rbp"}]


def test_instruction_ranges_use_full_analysis_and_protect_multibyte_nops() -> None:
    ranges = CaveFinder(_ScopedBinary())._instruction_ranges()

    expect(ranges == ((0x1001, 0x1009), (0x2000, 0x2005)))


def test_strict_instruction_ranges_protect_single_byte_nops() -> None:
    ranges = CaveFinder(_ScopedBinary(), protect_nop_instructions=True)._instruction_ranges()

    expect(ranges == ((0x1000, 0x1001), (0x1001, 0x1009), (0x2000, 0x2005)))
