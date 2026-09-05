"""Regression coverage for closed virtualization diagnostics on real ELF input."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect

_DATASET = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset"
_FIXTURE = _DATASET / "elf_vm_fpengineidxnb_x86_64"


def test_terminal_syscall_data_tail_does_not_report_partial_function(tmp_path: Path) -> None:
    """Bytes after a non-returning syscall are not treated as live instructions."""
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
        stats["functions_virtualized"] >= 1
        and stats["partial_virtualization_total"] == 0
        and stats["unsupported_functions_total"] == 0
    )


def test_strict_mode_accepts_complete_function_without_partial_diagnostic(tmp_path: Path) -> None:
    """Strict mode keeps a complete region eligible for virtualization."""
    expect(_FIXTURE.exists(), f"fixture missing: {_FIXTURE}")
    mutated = tmp_path / "strict_partial_rejection"
    shutil.copy(_FIXTURE, mutated)
    original_bytes = mutated.read_bytes()

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
        stats["functions_virtualized"] >= 1
        and stats["partial_virtualization_total"] == 0
        and stats["unsupported_functions_total"] == 0
        and mutated.read_bytes() != original_bytes
    )
