"""Characterization of SymbolicValidator early-return / guard contracts.

Pins, before the SymbolicValidator decomposition (clean-arch slice 5a
for the precheck split, slice 2a for the shellcode extraction):

* `_run_symbolic_precheck` fallback payload when the scope gate rejects
  the target or the pass (the path that returns before any angr import).
* `_compare_instruction_substitution_transition` `angr module not
  available` guard (returns before importing claripy).

No mocks / monkeypatch (CLAUDE.md §4): a real arch-reporting double and
a plain SimpleNamespace bridge object with no `angr` attribute.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from r2morph.validation.symbolic_validator import SymbolicValidator


class _ArchBinary:
    def __init__(self, arch_info: dict[str, Any]) -> None:
        self._arch_info = arch_info

    def get_arch_info(self) -> dict[str, Any]:
        return self._arch_info


_ELF64_X86_64 = {"format": "ELF64", "bits": 64, "arch": "x86_64"}


def _pass(name: str) -> dict[str, Any]:
    return {
        "pass_name": name,
        "mutations": [{"start_address": 0x401000, "end_address": 0x401003, "function_address": 0x401000}],
    }


def test_precheck_unsupported_target_returns_full_fallback_payload() -> None:
    binary = _ArchBinary({"format": "PE", "bits": 64, "arch": "x86_64"})
    payload = SymbolicValidator()._run_symbolic_precheck(binary, _pass("InstructionSubstitution"))
    assert payload == {
        "symbolic_requested": True,
        "symbolic_proven": False,
        "symbolic_backend": "angr",
        "symbolic_pass_name": "InstructionSubstitution",
        "covered_functions": [0x401000],
        "covered_address_ranges": [[0x401000, 0x401003]],
        "symbolic_status": "unsupported-target",
        "symbolic_reason": "falling back to structural validation",
    }


def test_precheck_unsupported_pass_returns_unsupported_pass_status() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    payload = SymbolicValidator()._run_symbolic_precheck(binary, _pass("ControlFlowFlattening"))
    assert payload["symbolic_requested"] is True
    assert payload["symbolic_proven"] is False
    assert payload["symbolic_status"] == "unsupported-pass"
    assert payload["symbolic_reason"] == "falling back to structural validation"
    assert payload["symbolic_pass_name"] == "ControlFlowFlattening"


def test_transition_returns_guard_when_bridge_has_no_angr_attribute() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    result = SymbolicValidator()._shellcode_checker._compare_instruction_substitution_transition(
        binary, {}, SimpleNamespace()
    )
    assert result == {
        "symbolic_transition_check_performed": False,
        "symbolic_transition_reason": "angr module not available",
    }


def test_transition_returns_guard_when_bridge_angr_is_none() -> None:
    binary = _ArchBinary(_ELF64_X86_64)
    result = SymbolicValidator()._shellcode_checker._compare_instruction_substitution_transition(
        binary, {}, SimpleNamespace(angr=None)
    )
    assert result == {
        "symbolic_transition_check_performed": False,
        "symbolic_transition_reason": "angr module not available",
    }
