"""Regression coverage for closed virtualization diagnostics on real ELF input."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect

_DATASET = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset"
_FIXTURE = _DATASET / "elf_vm_engarith_x86_64"


def test_straight_line_fallback_reports_partial_function_warning(tmp_path: Path) -> None:
    """A real fallback transform reports that the rest of the function stayed native."""
    expect(_FIXTURE.exists(), f"fixture missing: {_FIXTURE}")
    mutated = tmp_path / "partial_diagnostic"
    shutil.copy(_FIXTURE, mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260802}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(
        any(
            record["severity"] == "warning"
            and record["capability"]
            in {
                "calls",
                "memory_operands",
                "instruction_semantics",
                "provable_function_shape",
                "signals_and_system_calls",
            }
            and record["instruction_address"] > 0
            and "straight-line region was proven" in record["reason"]
            for record in stats["partial_virtualization"]
        )
    )


def test_strict_mode_rejects_partial_function_without_mutation(tmp_path: Path) -> None:
    """Strict mode leaves a real partially-proven function untouched."""
    expect(_FIXTURE.exists(), f"fixture missing: {_FIXTURE}")
    mutated = tmp_path / "strict_partial_rejection"
    shutil.copy(_FIXTURE, mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(
            config={"probability": 1.0, "seed": 20260802, "reject_partial_virtualization": True}
        ).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(
        stats["functions_virtualized"] == 0
        and stats["partial_virtualization_total"] == 0
        and any(
            record["severity"] == "error"
            and record["instruction_address"] > 0
            and "partial virtualization is disabled" in record["reason"]
            for record in stats["unsupported_functions"]
        )
    )
