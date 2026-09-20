"""Regression coverage for the bounded own-devirtualizer adversary."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from scripts.protection_adversary import analyze
from tests.utils.assertions import expect
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_engarithimm_x86_64"
_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "protection_adversary.py"


def test_protection_adversary_cli_resolves_repository_sibling_imports() -> None:
    result = run_command([sys.executable, _SCRIPT, "--help"], timeout=10)

    expect(result.returncode == 0, result.stderr)


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

    expect(any(row["classification"] == "unsupported_indirect_dispatch" for row in result["results"]))


def test_adversary_detects_encoded_live_dispatch_state(tmp_path: Path) -> None:
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

    expect(isinstance(dynamic, dict) and dynamic["state_encoding_detected"] is True, f"dynamic={dynamic!r}")
