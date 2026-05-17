"""Characterization of ValidationManager._validate_structural_mutation.

Pins the exact observable contract BEFORE the §6 extraction of a
StructuralValidator collaborator (CLAUDE.md §5: characterize first,
refactor next). The pre-existing suite only covers the patch-integrity
mismatch branch; the happy path, the full ValidationOutcome shape, and
the control-flow-failure branch are unpinned.

No mocks / monkeypatch (§4): a real Binary over the dataset/elf_x86_64
fixture, and a named real-Binary subclass that overrides one method to
force the control-flow-recovery failure path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2morph.core.binary import Binary
from r2morph.validation.manager import ValidationManager

_FIXTURE = Path("dataset/elf_x86_64")


def _work_copy(tmp_path: Path) -> Path:
    if not _FIXTURE.exists():
        pytest.skip("dataset/elf_x86_64 fixture not available")
    work = tmp_path / "vm_structural_sample"
    work.write_bytes(_FIXTURE.read_bytes())
    return work


def _first_function_address(binary: Binary) -> int:
    functions = binary.get_functions()
    if not functions:
        pytest.skip("fixture has no analyzed functions")
    first = functions[0]
    addr = first.get("offset", first.get("addr", first.get("address")))
    if addr is None:
        pytest.skip("function record has no recognizable address key")
    return int(addr)


class _ControlFlowFailureBinary(Binary):
    """Real Binary whose function disassembly always fails."""

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        raise OSError("disassembly unavailable")


class _ArchInfoFailureBinary(Binary):
    """Real Binary whose arch probe fails, so invariant detection raises."""

    def get_arch_info(self) -> dict[str, Any]:
        raise OSError("arch info unavailable")


def test_structural_mutation_happy_path_contract(tmp_path: Path) -> None:
    work = _work_copy(tmp_path)
    with Binary(work) as binary:
        binary.analyze()
        addr = _first_function_address(binary)
        original = binary.read_bytes(addr, 4)
        mutation = {
            "start_address": addr,
            "end_address": addr + len(original),
            "mutated_bytes": original.hex(),
        }
        outcome = ValidationManager(mode="structural")._structural_validator.validate_mutation(
            binary, mutation, validator_type="structural"
        )

    assert outcome.passed is True
    assert outcome.validator_type == "structural"
    assert outcome.scope == "mutation"
    assert outcome.issues == []
    assert outcome.metadata == {"pass_name": None}


def test_structural_mutation_patch_integrity_mismatch(tmp_path: Path) -> None:
    work = _work_copy(tmp_path)
    with Binary(work) as binary:
        binary.analyze()
        addr = _first_function_address(binary)
        original = binary.read_bytes(addr, 4)
        flipped = bytes((b ^ 0xFF) for b in original)
        mutation = {
            "start_address": addr,
            "end_address": addr + len(original),
            "mutated_bytes": flipped.hex(),
        }
        outcome = ValidationManager(mode="structural")._structural_validator.validate_mutation(
            binary, mutation, validator_type="structural"
        )

    assert outcome.passed is False
    assert len(outcome.issues) == 1
    issue = outcome.issues[0]
    assert issue.validator == "patch_integrity"
    assert issue.evidence["expected"] == flipped.hex()
    assert issue.evidence["actual"] == original.hex()


def test_structural_mutation_control_flow_failure(tmp_path: Path) -> None:
    work = _work_copy(tmp_path)
    with _ControlFlowFailureBinary(work) as binary:
        binary.analyze()
        addr = _first_function_address(binary)
        original = binary.read_bytes(addr, 4)
        mutation = {
            "start_address": addr,
            "end_address": addr + len(original),
            "mutated_bytes": original.hex(),
            "function_address": addr,
        }
        outcome = ValidationManager(mode="structural")._structural_validator.validate_mutation(
            binary, mutation, validator_type="structural"
        )

    assert outcome.passed is False
    assert "control_flow" in {issue.validator for issue in outcome.issues}


def test_capture_baseline_mode_off_returns_empty(tmp_path: Path) -> None:
    work = _work_copy(tmp_path)
    with Binary(work) as binary:
        binary.analyze()
        addr = _first_function_address(binary)
        result = ValidationManager(mode="off").capture_structural_baseline(binary, addr)
    assert result == {}


def test_capture_baseline_none_address_returns_empty(tmp_path: Path) -> None:
    work = _work_copy(tmp_path)
    with Binary(work) as binary:
        result = ValidationManager(mode="structural").capture_structural_baseline(binary, None)
    assert result == {}


def test_capture_baseline_zero_address_returns_empty(tmp_path: Path) -> None:
    work = _work_copy(tmp_path)
    with Binary(work) as binary:
        result = ValidationManager(mode="structural").capture_structural_baseline(binary, 0)
    assert result == {}


def test_capture_baseline_shape_contract(tmp_path: Path) -> None:
    work = _work_copy(tmp_path)
    with Binary(work) as binary:
        binary.analyze()
        addr = _first_function_address(binary)
        result = ValidationManager(mode="structural").capture_structural_baseline(binary, addr)

    assert set(result.keys()) == {"function_address", "invariant_count", "invariants"}
    assert result["function_address"] == addr
    assert result["invariant_count"] == len(result["invariants"])
    for inv in result["invariants"]:
        assert set(inv.keys()) == {"type", "location", "description", "details"}


def test_capture_baseline_invariant_failure_yields_empty_invariants(tmp_path: Path) -> None:
    work = _work_copy(tmp_path)
    with _ArchInfoFailureBinary(work) as binary:
        binary.analyze()
        addr = _first_function_address(binary)
        result = ValidationManager(mode="structural").capture_structural_baseline(binary, addr)

    assert result == {
        "function_address": addr,
        "invariant_count": 0,
        "invariants": [],
    }
