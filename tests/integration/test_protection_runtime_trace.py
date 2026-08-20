"""Regression coverage for bounded dynamic protection evidence."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import trace_execution

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"


def test_trace_execution_records_indirect_dispatch_for_protected_fixture(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    shutil.copyfile(_FIXTURE, protected)
    binary = Binary(protected, writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260820}).apply(binary)
        binary.save()
    finally:
        binary.close()

    result = trace_execution(protected)

    assert result["indirect_jump_count"] > 0


def test_trace_execution_correlates_dispatch_target_with_vm_context(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    shutil.copyfile(_FIXTURE, protected)
    binary = Binary(protected, writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260820}).apply(binary)
        binary.save()
    finally:
        binary.close()

    result = trace_execution(protected)
    assert any(
        isinstance(jump, dict)
        and all(field in jump for field in ("target", "vpc", "bytecode_base", "position"))
        and isinstance(jump["bytecode_base"], int)
        and jump["bytecode_base"] > 0
        for jump in result["indirect_jumps"]
    )
