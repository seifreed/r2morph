"""Regression coverage for the real protection maturity measurement harness."""

from __future__ import annotations

from pathlib import Path

from scripts.protection_maturity_baseline import (
    _PREVIEW_BYTES,
    _ArtifactAccumulator,
    _runtime_artifacts,
    _runtime_observables_equal,
    _semantic_run_matches,
    discover_executables,
    measure_fixture,
)
from tests.utils.assertions import expect

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
_FIXTURE = _DATASET / "elf_vm_arith_x86_64"


def test_measure_fixture_records_real_semantic_result(tmp_path: Path) -> None:
    result = measure_fixture(_FIXTURE, range(20260820, 20260821), tmp_path)

    expect(not (result["all_semantic_equal"] is not True))


def test_runtime_observables_detect_changed_stdout_digest() -> None:
    baseline = {
        "status": "completed",
        "return_code": 42,
        "stdout": {"sha256": "same", "size": 1},
        "stderr": {"sha256": "empty", "size": 0},
    }
    changed = {**baseline, "stdout": {"sha256": "different", "size": 1}}

    expect(not (_runtime_observables_equal(baseline, changed) is not False))


def test_runtime_artifacts_records_files_created_by_real_process(tmp_path: Path) -> None:
    program = tmp_path / "program"
    program.write_text(
        "#!/bin/sh\nprintf created > created.txt\n",
        encoding="utf-8",
    )
    program.chmod(0o700)

    result = _runtime_artifacts(program)

    expect(
        result["created_files"]
        == {
            "created.txt": {
                "sha256": "406effb1e9c59672c66a598c2b21e331b23b16c54024e96d6df3e7c173549791",
                "size": 7,
            }
        }
    )


def test_runtime_observables_detect_changed_created_file() -> None:
    baseline = {
        "status": "completed",
        "return_code": 0,
        "stdout": {"sha256": "empty", "size": 0},
        "stderr": {"sha256": "empty", "size": 0},
        "created_files": {"result.txt": {"sha256": "same", "size": 1}},
    }
    changed = {**baseline, "created_files": {"result.txt": {"sha256": "different", "size": 1}}}

    expect(not (_runtime_observables_equal(baseline, changed) is not False))


def test_artifact_accumulator_bounds_preview_for_large_stream() -> None:
    accumulator = _ArtifactAccumulator()
    accumulator.update(b"x" * (_PREVIEW_BYTES * 100))
    result = accumulator.result()

    expect(result["size"] == _PREVIEW_BYTES * 100)
    expect(len(result["preview_hex"]) == _PREVIEW_BYTES * 2)


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

    expect(not (_semantic_run_matches(baseline, runtime, run) is not False))


def test_discover_executables_excludes_relocatable_objects() -> None:
    fixtures = discover_executables(_DATASET)

    expect(_DATASET / "elf_x86_64.o" not in fixtures)
