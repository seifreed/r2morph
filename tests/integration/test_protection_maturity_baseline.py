"""Regression coverage for the real protection maturity measurement harness."""

from __future__ import annotations

from pathlib import Path

from scripts.protection_maturity_baseline import discover_executables, measure_fixture

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
_FIXTURE = _DATASET / "elf_vm_arith_x86_64"


def test_measure_fixture_records_real_semantic_result(tmp_path: Path) -> None:
    result = measure_fixture(_FIXTURE, range(20260820, 20260821), tmp_path)

    assert result["all_semantic_equal"] is True


def test_discover_executables_excludes_relocatable_objects() -> None:
    fixtures = discover_executables(_DATASET)

    assert _DATASET / "elf_x86_64.o" not in fixtures
