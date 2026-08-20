"""Characterization of the symbolic-scope gate (_supports_symbolic_scope).

Pins the exact current contract before the SymbolicScopeGate extraction
(clean-arch slice 1a). No mocks / monkeypatch (CLAUDE.md §4): a real
arch-reporting double implements the only Binary surface the gate uses
(get_arch_info), and the gate is exercised on a real SymbolicValidator.
"""

from __future__ import annotations

from typing import Any

from r2morph.validation.symbolic_validator import SymbolicValidator
from tests.utils.assertions import expect


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
    expect(not (supported is not True))
    expect(reason == "supported")
    expect(
        metadata
        == {
            "symbolic_backend": "angr",
            "symbolic_pass_name": "InstructionSubstitution",
            "covered_functions": [4198400],
            "covered_address_ranges": [[4198400, 4198403]],
        }
    )


def test_unsupported_target_non_elf_format() -> None:
    binary = _ArchBinary({"format": "PE", "bits": 64, "arch": "x86_64"})
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("InstructionSubstitution", [_mutation(0x401000, 0x401003)])
    )
    expect(not (supported is not False))
    expect(reason == "unsupported-target")


def test_unsupported_target_elf_but_32_bit() -> None:
    binary = _ArchBinary({"format": "ELF32", "bits": 32, "arch": "x86"})
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("InstructionSubstitution", [_mutation(0x401000, 0x401003)])
    )
    expect(not (supported is not False))
    expect(reason == "unsupported-target")


def test_unsupported_target_elf64_wrong_arch() -> None:
    binary = _ArchBinary({"format": "ELF64", "bits": 64, "arch": "arm64"})
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("InstructionSubstitution", [_mutation(0x401000, 0x401003)])
    )
    expect(not (supported is not False))
    expect(reason == "unsupported-target")


def test_unsupported_pass_name() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("ControlFlowFlattening", [_mutation(0x401000, 0x401003)])
    )
    expect(not (supported is not False))
    expect(reason == "unsupported-pass")


def test_no_mutations_returns_no_mutations() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    supported, reason, metadata = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", [])
    )
    expect(not (supported is not False))
    expect(reason == "no-mutations")
    expect(metadata["covered_functions"] == [])
    expect(metadata["covered_address_ranges"] == [])


def test_more_than_eight_mutations_is_unsupported_scope() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    mutations = [_mutation(0x401000 + i, 0x401001 + i) for i in range(9)]
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", mutations)
    )
    expect(not (supported is not False))
    expect(reason == "unsupported-scope")


def test_region_wider_than_sixteen_bytes_is_unsupported_scope() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    # end - start + 1 == 17 > 16
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", [_mutation(0x401000, 0x401010)])
    )
    expect(not (supported is not False))
    expect(reason == "unsupported-scope")


def test_exactly_sixteen_byte_region_is_supported() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    # end - start + 1 == 16, the inclusive boundary
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", [_mutation(0x401000, 0x40100F)])
    )
    expect(not (supported is not True))
    expect(reason == "supported")


def test_missing_function_address_is_unsupported_scope() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    supported, reason, _ = SymbolicValidator()._scope_gate._supports_symbolic_scope(
        binary, _pass("NopInsertion", [_mutation(0x401000, 0x401003, function_address=0)])
    )
    expect(not (supported is not False))
    expect(reason == "unsupported-scope")


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
    expect(not (supported is not True))
    expect(reason == "supported")
    expect(metadata["covered_functions"] == [4198400, 4202496])
    expect(metadata["covered_address_ranges"] == [[4198416, 4198419], [4198400, 4198403], [4198432, 4198435]])
