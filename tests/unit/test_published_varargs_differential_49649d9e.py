"""Regression checks for the bounded varargs differential evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/protection-differential-varargs-local-2026-11-15-49649d9e.json"
_SUMMARY = _ROOT / "docs/protection-differential-varargs-local-2026-11-15-49649d9e-summary.json"
_SOURCE_COMMIT = "49649d9e5b7f7bb1c5d98279fa8fec56553af2cb"
_FIXTURE_SHA256 = "ac58d651a1110013d10f545fba83d7ec653da37e902d25a69904d4e067b436c0"
_REPORT_SHA256 = "8349035f7eacfdde2f2e0175465d68bd523e0e1d3d4208eb654fc61099f873ad"
_EXPECTED_COMPLETE_COVERAGE_PERCENT = 100.0
_EXPECTED_EXIT_CODE = 69
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")


def _report() -> dict[str, object]:
    return json.loads(_REPORT.read_text(encoding="utf-8"))


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def test_published_varargs_report_is_bound_to_source_and_fixture() -> None:
    summary = _summary()
    fixture = summary["fixture"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_report"] == _REPORT.name
        and summary["source_report_sha256"] == _REPORT_SHA256
        and hashlib.sha256(_REPORT.read_bytes()).hexdigest() == _REPORT_SHA256
        and fixture["sha256"] == _FIXTURE_SHA256
        and hashlib.sha256((_ROOT / fixture["path"]).read_bytes()).hexdigest() == _FIXTURE_SHA256
    )


def test_published_varargs_report_records_complete_applied_evidence() -> None:
    report = _report()
    summary = report["summary"]

    expect(
        report["fixtures"][0]["sample"] == "elf_vm_varargs_x86_64"
        and summary["applied_runs"] == summary["successful_seed_runs"] == 1
        and summary["complete_evidence_runs"] == 1
        and summary["complete_evidence_missing_runs"] == 0
        and summary["complete_evidence_coverage_percent"] == _EXPECTED_COMPLETE_COVERAGE_PERCENT
        and summary["failed_seed_runs"] == summary["error_runs"] == 0
    )


def test_published_varargs_report_records_matching_runtime_observables() -> None:
    fixture = _report()["fixtures"][0]
    run = fixture["runs"][0]

    expect(
        fixture["baseline_runtime"]["return_code"] == run["runtime"]["return_code"] == _EXPECTED_EXIT_CODE
        and fixture["baseline_unicorn"]["exit_code"] == run["unicorn"]["exit_code"] == _EXPECTED_EXIT_CODE
        and fixture["baseline_qemu"]["exit_code"] == run["qemu"]["exit_code"] == _EXPECTED_EXIT_CODE
        and run["runtime_observable_equal"] is True
        and run["runtime_input_observable_equal"] is True
    )


def test_published_varargs_report_records_matching_output_hashes() -> None:
    fixture = _report()["fixtures"][0]
    run = fixture["runs"][0]

    expect(
        fixture["baseline_runtime"]["stdout"]["sha256"] == run["runtime"]["stdout"]["sha256"]
        and fixture["baseline_runtime"]["stderr"]["sha256"] == run["runtime"]["stderr"]["sha256"]
    )


def test_published_varargs_summary_records_emulation_environment() -> None:
    context = _summary()["execution_context"]

    expect(
        context["runtime"] == "Linux arm64 with x86-64 user-mode emulation"
        and context["python"] == "3.12.16"
        and context["qemu_x86_64"] == "10.0.13"
        and context["radare2"] == "6.2.2"
    )


def test_published_varargs_summary_records_bounded_manual_decompiler_observation() -> None:
    observation = _summary()["manual_decompiler_observation"]

    expect(
        observation["original"]["function"] == "sum_variadic"
        and observation["original"]["decompilation_completed"] is True
        and observation["protected"]["function"] == "_start"
        and observation["protected"]["decompilation_completed"] is True
        and observation["counted_as_benchmark_tool_slot"] is False
    )


def test_published_varargs_evidence_keeps_general_readiness_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        readiness["status"] == "blocked"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_published_varargs_report_contains_no_host_paths() -> None:
    content = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in content for marker in _PATH_MARKERS))
