"""Verify hash-bound three-platform continuous fuzz evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/continuous-fuzz-2026-11-14-43654009381-summary.json"
_PLATFORMS = ("macos-15", "ubuntu-latest", "windows-latest")
_SOURCE_COMMIT = "7374619a98b4cd4fccfa5821027262b408049ffd"
_WORKFLOW_RUN = 43_654_009_381
_CASES_PER_PLATFORM = 5_000
_TOTAL_TARGET_RUNS = 150_000
_ZERO = 0
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


def test_continuous_fuzz_summary_binds_reports_to_successful_main_run() -> None:
    summary = _json(_SUMMARY)
    reports = summary["platforms"]

    expect(
        summary["workflow_run_id"] == _WORKFLOW_RUN
        and summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_conclusion"] == "success"
        and set(reports) == set(_PLATFORMS)
        and all(
            hashlib.sha256((_ROOT / "docs" / reports[platform]["path"]).read_bytes()).hexdigest()
            == reports[platform]["sha256"]
            for platform in _PLATFORMS
        )
    )


def test_continuous_fuzz_reports_cover_all_targets_without_failures() -> None:
    summary = _json(_SUMMARY)
    reports = summary["platforms"]

    expect(
        summary["total_target_runs"] == _TOTAL_TARGET_RUNS
        and summary["failure_count"] == _ZERO
        and all(
            reports[platform]["cases"] == _CASES_PER_PLATFORM
            and reports[platform]["failure_count"] == _ZERO
            and reports[platform]["target_runs"] == dict.fromkeys(_EXPECTED_TARGETS, _CASES_PER_PLATFORM)
            for platform in _PLATFORMS
        )
    )
