import contextlib
import io
import os
import platform
import runpy
import signal
import sys
from pathlib import Path

import pytest

from scripts.vm_semantic_campaign import (
    _DEFAULT_SEEDS,
    _PASSABLE_FIXTURE_STATUSES,
    _corpus_fixture_counts,
    _error_result,
    _execution_observation,
    _load_coverage,
    _qemu_observables_equal,
    _qemu_summary,
    _select_fixture_shard,
    _semantic_failure_result,
    merge_campaign_reports,
    run_campaign,
)
from tests.utils.assertions import expect

_MERGED_SEED_COUNT = 2
_MERGED_FIXTURE_COUNT = 2
_PARALLEL_FIXTURE_COUNT = 2
_UNWIND_SSA_FIXTURE_COUNT = 2
_MAX_ERROR_MESSAGE_LENGTH = 240


def test_vm_semantic_campaign_defaults_to_three_deterministic_seeds() -> None:
    expect(_DEFAULT_SEEDS == (20260916, 20260917, 20260918))


def test_vm_semantic_campaign_only_counts_fully_virtualized_fixtures_as_passed() -> None:
    expect(frozenset({"passed"}) == _PASSABLE_FIXTURE_STATUSES)


def test_vm_semantic_campaign_script_resolves_local_imports() -> None:
    original_argv = sys.argv
    original_path = sys.path.copy()
    output = io.StringIO()
    sys.argv = ["scripts/vm_semantic_campaign.py", "--help"]
    sys.path.insert(0, str(Path("scripts").resolve()))
    try:
        with contextlib.redirect_stdout(output):
            runpy.run_path("scripts/vm_semantic_campaign.py", run_name="__main__")
    except SystemExit as error:
        expect(error.code == 0)
    finally:
        sys.argv = original_argv
        sys.path = original_path

    expect("--generated-corpus" in output.getvalue())


def test_vm_semantic_campaign_counts_generated_and_repository_fixtures() -> None:
    counts = _corpus_fixture_counts((Path("fixtures/dataset/elf_vm_memwidth_x86_64"), Path("generated_c_gcc-o0")))

    expect(counts == {"generated-corpus": 1, "repository-fixtures": 1})


def test_vm_semantic_campaign_qemu_oracle_requires_matching_completed_results() -> None:
    completed = {"status": "completed", "exit_code": 0}
    changed = {"status": "completed", "exit_code": 1}
    unavailable = {"status": "unavailable", "exit_code": None}
    timed_out = {"status": "timeout", "exit_code": None}

    expect(
        _qemu_observables_equal(completed, completed)
        and not _qemu_observables_equal(completed, changed)
        and _qemu_observables_equal(unavailable, unavailable)
        and _qemu_observables_equal(timed_out, timed_out)
    )


def test_vm_semantic_campaign_qemu_summary_counts_independent_pairs() -> None:
    summary = _qemu_summary(
        [
            {
                "qemu": {
                    "original": {"status": "completed"},
                    "mutated": {"status": "completed"},
                    "observables_equal": True,
                }
            },
            {
                "qemu": {
                    "original": {"status": "unavailable"},
                    "mutated": {"status": "unavailable"},
                    "observables_equal": True,
                }
            },
            {
                "qemu": {
                    "original": {"status": "timeout"},
                    "mutated": {"status": "timeout"},
                    "observables_equal": True,
                }
            },
            {
                "qemu": {
                    "original": {"status": "completed", "exit_code": 0},
                    "mutated": {"status": "completed", "exit_code": 1},
                    "observables_equal": False,
                }
            },
            {},
        ]
    )

    expect(
        summary
        == {
            "oracle": "qemu-x86_64",
            "completed_pairs": 1,
            "unavailable_pairs": 2,
            "divergent_pairs": 1,
            "missing_pairs": 1,
        }
    )


def test_vm_semantic_campaign_shards_are_disjoint_and_complete() -> None:
    fixtures = tuple(Path(f"fixture-{index}") for index in range(7))
    shards = tuple(_select_fixture_shard(fixtures, index, 3) for index in range(3))

    expect(set().union(*map(set, shards)) == set(fixtures) and len(set().intersection(*map(set, shards))) == 0)


def test_vm_semantic_campaign_rejects_unsupported_functions_with_equal_observables() -> None:
    result = _semantic_failure_result(
        {
            "unsupported_functions_total": 1,
            "unsupported_functions": [{"capability": "calls", "severity": "error"}],
            "unsupported_function_capabilities": {"calls": 1},
        },
        1,
        {"status": "completed"},
        {"status": "completed"},
    )

    expect(
        result["status"] == "passed_with_unsupported"
        and result["observables_equal"] is True
        and result["unsupported_function_details"] == [{"capability": "calls", "severity": "error"}]
    )


def test_vm_semantic_campaign_rejects_unsupported_functions_with_divergent_observables() -> None:
    result = _semantic_failure_result(
        {
            "unsupported_functions_total": 1,
            "unsupported_functions": [{"capability": "calls", "severity": "error"}],
            "unsupported_function_capabilities": {"calls": 1},
        },
        1,
        {"returncode": 0},
        {"returncode": 1},
    )

    expect(result["status"] == "semantic_mismatch" and result["observables_equal"] is False)


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


def test_vm_semantic_error_result_bounds_diagnostic_message() -> None:
    result = _error_result(ValueError("line one\n" + "x" * 400))

    expect(
        result["status"] == "error"
        and result["error_type"] == "ValueError"
        and len(result["error_message"]) == _MAX_ERROR_MESSAGE_LENGTH
    )


@pytest.mark.skipif(platform.system() != "Linux", reason="native VM parity campaign requires Linux ELF execution")
def test_vm_semantic_campaign_fixture_virtualizes_with_native_parity() -> None:
    report = run_campaign(
        Path("fixtures/dataset"),
        _load_coverage(Path("docs/virtualization-coverage.json")),
        seed=20260916,
        fixture_selection=(Path("fixtures/dataset/elf_vm_memwidth_x86_64"),),
    )

    fixture_categories = {
        category
        for category, fixture_names in _load_coverage(Path("docs/virtualization-coverage.json")).items()
        if "elf_vm_memwidth_x86_64" in fixture_names
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
        and report["capability_summary"]["memory"]["status"] == "campaign-measured"
        and report["capability_summary"]["unwinding-exceptions"]["status"] == "not-covered-by-fixture-campaign"
        and report["capability_summary"]["ssa-liveness"]["status"] == "not-covered-by-fixture-campaign",
        f"vm semantic campaign report: {report}",
    )


@pytest.mark.skipif(platform.system() != "Linux", reason="native VM parity campaign requires Linux ELF execution")
def test_vm_semantic_campaign_measures_unwind_and_ssa_fixture_contracts() -> None:
    report = run_campaign(
        Path("fixtures/dataset"),
        _load_coverage(Path("docs/virtualization-coverage.json")),
        seed=20260916,
        fixture_selection=("elf_vm_unwind_x86_64", "elf_vm_multiexit_x86_64"),
    )

    expect(
        report["status"] == "passed"
        and report["passed_count"] == _UNWIND_SSA_FIXTURE_COUNT
        and report["capability_summary"]["unwinding-exceptions"]["status"] == "campaign-measured"
        and report["capability_summary"]["ssa-liveness"]["status"] == "campaign-measured"
    )


@pytest.mark.skipif(platform.system() != "Linux", reason="native VM parity campaign requires Linux ELF execution")
def test_vm_semantic_campaign_workers_preserve_native_parity() -> None:
    coverage = _load_coverage(Path("docs/virtualization-coverage.json"))
    report = run_campaign(
        Path("fixtures/dataset"),
        coverage,
        seed=20260916,
        fixture_selection=("elf_vm_memwidth_x86_64", "elf_vm_shift_x86_64"),
    )

    expect(report["status"] == "passed" and report["passed_count"] == _PARALLEL_FIXTURE_COUNT)


@pytest.mark.skipif(platform.system() != "Linux", reason="native VM parity campaign requires Linux ELF execution")
def test_vm_semantic_campaign_merges_multiple_seed_runs_without_failures() -> None:
    coverage = _load_coverage(Path("docs/virtualization-coverage.json"))
    reports = tuple(
        run_campaign(
            Path("fixtures/dataset"),
            coverage,
            seed=seed,
            fixture_selection=("elf_vm_shift_x86_64",),
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
        and merged["corpus_fixture_counts"] == {"generated-corpus": 1, "repository-fixtures": 2}
    )


@pytest.mark.skipif(platform.system() != "Linux", reason="native VM parity campaign requires Linux ELF execution")
def test_vm_semantic_campaign_merges_disjoint_shards_with_duplicate_seed() -> None:
    coverage = _load_coverage(Path("docs/virtualization-coverage.json"))
    reports = tuple(
        run_campaign(
            Path("fixtures/dataset"),
            coverage,
            seed=20260916,
            fixture_selection=(fixture,),
        )
        for fixture in ("elf_vm_shift_x86_64", "elf_vm_memwidth_x86_64")
    )
    merged = merge_campaign_reports(reports, allow_duplicate_seeds=True)

    expect(
        merged["status"] == "passed"
        and merged["seed_count"] == 1
        and merged["fixture_count"] == _MERGED_FIXTURE_COUNT
        and merged["passed_count"] == _MERGED_FIXTURE_COUNT
        and merged["failed_count"] == 0
    )


def test_vm_semantic_workflow_requires_per_fixture_function_evidence() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "differential-corpus.yml"
    content = workflow.read_text(encoding="utf-8")

    expect(
        'report.get("fixture_results", [])' in content
        and 'row.get("functions_virtualized")' in content
        and 'row.get("status") != "passed"' in content
        and 'row.get("unsupported_function_details", [])' in content
        and '"termination_signal" not in row["original"]' in content
        and "merge_campaign_reports(tuple(reports), allow_duplicate_seeds=True)" in content
    )


def test_vm_semantic_workflow_publishes_regression_capability_contracts() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "differential-corpus.yml"
    content = workflow.read_text(encoding="utf-8")

    expect(
        "required_vm_contracts" in content
        and '"unwinding-exceptions"' in content
        and '"ssa-liveness"' in content
        and '"regression-covered"' in content
        and "vm-semantic-contracts-merged.json" in content
        and "vm-semantic-campaign-aggregate" in content
    )


def test_vm_semantic_workflow_requires_campaign_coverage_for_unwind_and_ssa() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "differential-corpus.yml"
    content = workflow.read_text(encoding="utf-8")

    expect(
        "matrix:\n        seed: [20260916, 20260917, 20260918]" in content
        and 'expected_corpus_counts = {"generated-corpus": 408, "repository-fixtures": 453}' in content
        and 'report["corpus_fixture_counts"]' in content
        and 'report["fixture_count"] != sum(expected_corpus_counts.values())' in content
        and 'categories.get("uncategorized", {}).get("fixture_count", 0) != 408' in content
        and "qemu-user" in content
        and 'row.get("qemu")' in content
        and "incomplete independent observable evidence" in content
        and 'qemu_summary.get("completed_pairs")' in content
        and 'summary["status"] not in {"campaign-measured", "not-covered-by-fixture-campaign"}' in content
        and '"unwinding-exceptions",\n              "tls-signals"' in content
        and '"fp-simd",\n              "ssa-liveness"' in content
    )
