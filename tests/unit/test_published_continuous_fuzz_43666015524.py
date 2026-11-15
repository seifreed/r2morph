"""Verify hash-bound three-platform continuous fuzz evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/continuous-fuzz-2026-11-15-f8586a1-summary.json"
_PLATFORMS = ("macos-15", "ubuntu-latest", "windows-latest")
_SOURCE_REVISION = "f8586a1beb0068d53bcc9ebaf3009ce0e2e8e375"
_WORKFLOW_RUN_ID = 43_666_015_524
_CASES_PER_TARGET = 5_000
_TARGET_COUNT = 10
_TARGET_RUNS_PER_PLATFORM = 50_000
_TARGET_RUNS_TOTAL = 150_000
_ZERO = 0
_SOURCE_ARTIFACT_SHA256 = {
    "macos-15": "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    "ubuntu-latest": "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    "windows-latest": "03cdcbe0b6a4fe2a373d605ba4bc1ed40d669674ba30614feb61988b7a1bd21c",
}
_EXPECTED_TARGETS = (
    "assembling",
    "binary_parsers",
    "binary_rewriter",
    "elf_header_parser",
    "macho_load_commands",
    "pe_header_parser",
    "relocations",
    "vm_bytecode",
    "vm_dispatcher",
    "vm_instruction_decoder",
)


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_published_fuzz_summary_binds_reports_to_successful_main_run() -> None:
    summary = _json(_SUMMARY_PATH)
    reports = summary["reports"]

    expect(
        summary["workflow_run_id"] == _WORKFLOW_RUN_ID
        and summary["source_revision"] == _SOURCE_REVISION
        and summary["workflow_conclusion"] == "success"
        and set(reports) == set(_PLATFORMS)
        and all(
            hashlib.sha256((_ROOT / reports[platform]["path"]).read_bytes()).hexdigest() == reports[platform]["sha256"]
            and reports[platform]["source_artifact_sha256"] == _SOURCE_ARTIFACT_SHA256[platform]
            and reports[platform]["job_conclusion"] == "success"
            for platform in _PLATFORMS
        )
    )


def test_published_fuzz_reports_cover_all_targets_without_failures() -> None:
    summary = _json(_SUMMARY_PATH)

    expect(
        summary["cases_per_target_per_platform"] == _CASES_PER_TARGET
        and summary["target_count"] == _TARGET_COUNT
        and summary["target_runs_per_platform"] == _TARGET_RUNS_PER_PLATFORM
        and summary["target_runs_total"] == _TARGET_RUNS_TOTAL
        and summary["failures_per_platform"] == _ZERO
        and all(
            (report := _json(_ROOT / summary["reports"][platform]["path"]))["cases"] == _CASES_PER_TARGET
            and report["failure_count"] == _ZERO
            and report["failures"] == []
            and report["target_runs"] == dict.fromkeys(_EXPECTED_TARGETS, _CASES_PER_TARGET)
            for platform in _PLATFORMS
        )
    )


def test_published_fuzz_reports_preserve_parser_diagnostics() -> None:
    summary = _json(_SUMMARY_PATH)

    expect(
        summary["parser_diagnostics_per_platform"] == {"macho_load_commands.warning": 103}
        and all(
            _json(_ROOT / summary["reports"][platform]["path"])["parser_diagnostic_counts"]
            == summary["parser_diagnostics_per_platform"]
            for platform in _PLATFORMS
        )
    )
