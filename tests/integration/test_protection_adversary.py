"""Regression coverage for the bounded own-devirtualizer adversary."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from scripts.protection_adversary import analyze

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"


def test_adversary_classifies_encrypted_dispatch_as_unsupported(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    shutil.copyfile(_FIXTURE, protected)
    binary = Binary(protected, writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260820}).apply(binary)
        binary.save()
    finally:
        binary.close()

    result = analyze(protected, limit=3)

    assert any(row["classification"] == "unsupported_indirect_dispatch" for row in result["results"])


def test_adversary_recovers_live_dispatch_sequence(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    shutil.copyfile(_FIXTURE, protected)
    binary = Binary(protected, writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260820}).apply(binary)
        binary.save()
    finally:
        binary.close()

    result = analyze(protected, limit=3)
    dynamic = result["dynamic_recovery"]

    assert isinstance(dynamic, dict) and dynamic["recovered"] is True
