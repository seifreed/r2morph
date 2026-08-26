"""Regression tests for the versioned support contract."""

from __future__ import annotations

import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MIN_CONCRETE_PASSES = 20


def test_support_matrix_declares_linux_elf_x86_64_as_official() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))

    expect(
        matrix["official_target"] == {"os": "linux", "format": "ELF", "architecture": "x86-64", "status": "supported"}
    )


def test_support_matrix_evidence_paths_exist() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    paths = [
        evidence for entry in matrix["passes"] for evidence in entry["evidence"] if not evidence.startswith("http")
    ]

    expect(all((_ROOT / evidence).exists() for evidence in paths), f"missing evidence: {paths}")


def test_support_matrix_enumerates_concrete_unique_passes() -> None:
    matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    names = [entry["name"] for entry in matrix["passes"]]

    expect(
        len(names) == len(set(names)) and "experimental-passes" not in names and len(names) >= _MIN_CONCRETE_PASSES,
        "support matrix must enumerate concrete passes without duplicates",
    )
