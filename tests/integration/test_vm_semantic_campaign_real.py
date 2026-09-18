import os
import signal
from pathlib import Path

from scripts.vm_semantic_campaign import _execution_observation, _load_coverage, merge_campaign_reports, run_campaign
from tests.utils.assertions import expect

_MERGED_SEED_COUNT = 2
_MERGED_FIXTURE_COUNT = 2


def test_vm_semantic_observation_records_created_files(tmp_path: Path) -> None:
    program = tmp_path / "file_writer"
    program.write_text("#!/bin/sh\nprintf created > result.txt\n", encoding="utf-8")
    program.chmod(0o700)

    observation = _execution_observation(program, 5.0, tmp_path / "run")

    expect(
        observation["created_files"]
        == {
            "result.txt": {
                "sha256": "406effb1e9c59672c66a598c2b21e331b23b16c54024e96d6df3e7c173549791",
                "size": 7,
                "mode": 0o644,
            }
        }
    )


def test_vm_semantic_observation_records_signal_termination(tmp_path: Path) -> None:
    program = tmp_path / "signal_sender"
    program.write_text(
        "#!/usr/bin/env python3\nimport os\nimport signal\nos.kill(os.getpid(), signal.SIGTERM)\n",
        encoding="utf-8",
    )
    program.chmod(0o700)

    observation = _execution_observation(program, 5.0, tmp_path / "run")

    expected_signal = signal.SIGTERM if os.name == "posix" else None
    expect(observation["termination_signal"] == expected_signal)


def test_vm_semantic_campaign_fixture_virtualizes_with_native_parity() -> None:
    report = run_campaign(
        Path("fixtures/dataset"),
        _load_coverage(Path("docs/virtualization-coverage.json")),
        seed=20260916,
        fixture_names=("elf_vm_shift_x86_64",),
    )

    fixture_categories = {
        category
        for category, fixture_names in _load_coverage(Path("docs/virtualization-coverage.json")).items()
        if "elf_vm_shift_x86_64" in fixture_names
    }
    expect(
        report["status"] == "passed"
        and report["passed_count"] == 1
        and report["failures"] == []
        and report["fixture_results"][0]["functions_virtualized"] >= 1
        and report["fixture_results"][0]["unsupported_functions"] == 0
        and report["fixture_results"][0]["observables_equal"] is True
        and report["fixture_results"][0]["original"]["created_files"] == {}
        and report["fixture_results"][0]["mutated"]["created_files"] == {}
        and all(
            report["category_summary"][category]["passed_count"]
            == report["category_summary"][category]["fixture_count"]
            and report["category_summary"][category]["failed_count"] == 0
            for category in fixture_categories
        )
    )


def test_vm_semantic_campaign_merges_multiple_seed_runs_without_failures() -> None:
    coverage = _load_coverage(Path("docs/virtualization-coverage.json"))
    reports = tuple(
        run_campaign(
            Path("fixtures/dataset"),
            coverage,
            seed=seed,
            fixture_names=("elf_vm_shift_x86_64",),
        )
        for seed in (20260916, 20260917)
    )
    merged = merge_campaign_reports(reports)

    expect(
        merged["status"] == "passed"
        and merged["seed_count"] == _MERGED_SEED_COUNT
        and merged["fixture_count"] == _MERGED_FIXTURE_COUNT
        and merged["passed_count"] == _MERGED_FIXTURE_COUNT
        and merged["failed_count"] == 0
        and len(merged["fixture_results"]) == _MERGED_FIXTURE_COUNT
        and not merged["failures"]
    )


def test_vm_semantic_workflow_requires_per_fixture_function_evidence() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "differential-corpus.yml"
    content = workflow.read_text(encoding="utf-8")

    expect(
        'report.get("fixture_results", [])' in content
        and 'row.get("functions_virtualized")' in content
        and 'row.get("unsupported_functions") != 0' in content
        and '"termination_signal" not in row["original"]' in content
    )
