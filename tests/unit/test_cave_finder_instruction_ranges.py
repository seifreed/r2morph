"""Regression tests for cave validation across scoped mutation analysis."""

from __future__ import annotations

from typing import Any

from r2morph.relocations.cave_finder import CaveFinder
from tests.utils.assertions import expect

_SCOPED_FUNCTION_ADDRESS = 0x1000
_UNSCOPED_FUNCTION_ADDRESS = 0x2000
_ANALYZED_FUNCTION_COUNT = 2
_QUERY_COUNT = 2


class _AnalysisApi:
    def cmdj(self, command: str) -> list[dict[str, int]]:
        expect(command == "aflj")
        return [{"offset": _SCOPED_FUNCTION_ADDRESS}, {"offset": _UNSCOPED_FUNCTION_ADDRESS}]


class _ScopedBinary:
    r2 = _AnalysisApi()

    def __init__(self) -> None:
        self.disassembly_calls = 0

    def get_functions(self) -> list[dict[str, int]]:
        return [{"offset": _SCOPED_FUNCTION_ADDRESS}]

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        self.disassembly_calls += 1
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


def test_cave_finder_cached_ranges_preserve_instruction_boundaries() -> None:
    binary = _ScopedBinary()
    finder = CaveFinder(binary, cache_instruction_ranges=True)

    first = finder._get_instruction_ranges()
    second = finder._get_instruction_ranges()

    expect(first == second == ((0x1001, 0x1009), (0x2000, 0x2005)))


def test_cave_finder_cached_ranges_disassemble_each_function_once() -> None:
    binary = _ScopedBinary()
    finder = CaveFinder(binary, cache_instruction_ranges=True)

    finder._get_instruction_ranges()
    finder._get_instruction_ranges()

    expect(binary.disassembly_calls == _ANALYZED_FUNCTION_COUNT)


def test_cave_finder_uncached_ranges_observe_each_query() -> None:
    binary = _ScopedBinary()
    finder = CaveFinder(binary)

    finder._get_instruction_ranges()
    finder._get_instruction_ranges()

    expect(binary.disassembly_calls == _ANALYZED_FUNCTION_COUNT * _QUERY_COUNT)
