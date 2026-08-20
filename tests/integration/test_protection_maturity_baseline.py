"""Regression coverage for the real protection maturity measurement harness."""

from __future__ import annotations

from pathlib import Path

from scripts.protection_maturity_baseline import (
    _PREVIEW_BYTES,
    _ArtifactAccumulator,
    _runtime_observables_equal,
    _semantic_run_matches,
    discover_executables,
    measure_fixture,
)

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
_FIXTURE = _DATASET / "elf_vm_arith_x86_64"


def test_measure_fixture_records_real_semantic_result(tmp_path: Path) -> None:
    result = measure_fixture(_FIXTURE, range(20260820, 20260821), tmp_path)

    assert result["all_semantic_equal"] is True


def test_runtime_observables_detect_changed_stdout_digest() -> None:
    baseline = {
        "status": "completed",
        "return_code": 42,
        "stdout": {"sha256": "same", "size": 1},
        "stderr": {"sha256": "empty", "size": 0},
    }
    changed = {**baseline, "stdout": {"sha256": "different", "size": 1}}

    assert _runtime_observables_equal(baseline, changed) is False


def test_artifact_accumulator_bounds_preview_for_large_stream() -> None:
    accumulator = _ArtifactAccumulator()
    accumulator.update(b"x" * (_PREVIEW_BYTES * 100))
    result = accumulator.result()

    assert result["size"] == _PREVIEW_BYTES * 100
    assert len(result["preview_hex"]) == _PREVIEW_BYTES * 2


def test_semantic_run_rejects_invalid_emulator_status() -> None:
    baseline = {"status": "completed", "exit_code": 42}
    runtime = {
        "status": "error",
        "error_type": "OSError",
        "stdout": {"sha256": "empty", "size": 0},
        "stderr": {"sha256": "empty", "size": 0},
    }
    run = {
        "status": "passed",
        "runtime": runtime,
        "unicorn": {"status": "no_exit_syscall", "exit_code": None},
    }

    assert _semantic_run_matches(baseline, runtime, run) is False


def test_discover_executables_excludes_relocatable_objects() -> None:
    fixtures = discover_executables(_DATASET)

    assert _DATASET / "elf_x86_64.o" not in fixtures
