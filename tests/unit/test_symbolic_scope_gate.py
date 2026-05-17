"""Characterization of the symbolic-scope gate (_supports_symbolic_scope).

Pins the exact current contract before the SymbolicScopeGate extraction
(clean-arch slice 1a). No mocks / monkeypatch (CLAUDE.md §4): a real
arch-reporting double implements the only Binary surface the gate uses
(get_arch_info), and the gate is exercised on a real SymbolicValidator.
"""

from __future__ import annotations

from typing import Any

from r2morph.validation.symbolic_validator import SymbolicValidator


class _ArchBinary:
    """Minimal real Binary stand-in exposing only get_arch_info()."""

    def __init__(self, arch_info: dict[str, Any]) -> None:
        self._arch_info = arch_info

    def get_arch_info(self) -> dict[str, Any]:
        return self._arch_info


_ELF64_X86_64 = {"format": "ELF64", "bits": 64, "arch": "x86_64"}


def _mutation(start: Any, end: Any, function_address: Any = 0x401000) -> dict[str, Any]:
    return {
        "start_address": start,
        "end_address": end,
        "function_address": function_address,
    }


def _pass(name: str, mutations: list[dict[str, Any]]) -> dict[str, Any]:
    return {"pass_name": name, "mutations": mutations}


def test_supported_elf64_x86_64_instruction_substitution() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    supported, reason, metadata = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("InstructionSubstitution", [_mutation(0x401000, 0x401003)])
    )
    assert supported is True
    assert reason == "supported"
    assert metadata == {
        "symbolic_backend": "angr",
        "symbolic_pass_name": "InstructionSubstitution",
        "covered_functions": [0x401000],
        "covered_address_ranges": [[0x401000, 0x401003]],
    }


def test_unsupported_target_non_elf_format() -> None:
    binary = _ArchBinary({"format": "PE", "bits": 64, "arch": "x86_64"})
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("InstructionSubstitution", [_mutation(0x401000, 0x401003)])
    )
    assert supported is False
    assert reason == "unsupported-target"


def test_unsupported_target_elf_but_32_bit() -> None:
    binary = _ArchBinary({"format": "ELF32", "bits": 32, "arch": "x86"})
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("InstructionSubstitution", [_mutation(0x401000, 0x401003)])
    )
    assert supported is False
    assert reason == "unsupported-target"


def test_unsupported_target_elf64_wrong_arch() -> None:
    binary = _ArchBinary({"format": "ELF64", "bits": 64, "arch": "arm64"})
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("InstructionSubstitution", [_mutation(0x401000, 0x401003)])
    )
    assert supported is False
    assert reason == "unsupported-target"


def test_unsupported_pass_name() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("ControlFlowFlattening", [_mutation(0x401000, 0x401003)])
    )
    assert supported is False
    assert reason == "unsupported-pass"


def test_no_mutations_returns_no_mutations() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    supported, reason, metadata = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", [])
    )
    assert supported is False
    assert reason == "no-mutations"
    assert metadata["covered_functions"] == []
    assert metadata["covered_address_ranges"] == []


def test_more_than_eight_mutations_is_unsupported_scope() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    mutations = [_mutation(0x401000 + i, 0x401001 + i) for i in range(9)]
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", mutations)
    )
    assert supported is False
    assert reason == "unsupported-scope"


def test_region_wider_than_sixteen_bytes_is_unsupported_scope() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    # end - start + 1 == 17 > 16
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", [_mutation(0x401000, 0x401010)])
    )
    assert supported is False
    assert reason == "unsupported-scope"


def test_exactly_sixteen_byte_region_is_supported() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    # end - start + 1 == 16, the inclusive boundary
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", [_mutation(0x401000, 0x40100F)])
    )
    assert supported is True
    assert reason == "supported"


def test_missing_function_address_is_unsupported_scope() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", [_mutation(0x401000, 0x401003, function_address=0)])
    )
    assert supported is False
    assert reason == "unsupported-scope"


def test_metadata_covered_functions_sorted_unique_and_ranges_parse_hex() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    mutations = [
        _mutation("0x401010", "0x401013", function_address="0x402000"),
        _mutation("0x401000", "0x401003", function_address="0x401000"),
        _mutation("0x401020", "0x401023", function_address="0x401000"),
    ]
    supported, reason, metadata = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("RegisterSubstitution", mutations)
    )
    assert supported is True
    assert reason == "supported"
    assert metadata["covered_functions"] == [0x401000, 0x402000]
    assert metadata["covered_address_ranges"] == [
        [0x401010, 0x401013],
        [0x401000, 0x401003],
        [0x401020, 0x401023],
    ]
