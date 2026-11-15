"""Pin current-main continuous fuzz evidence to its workflow and reports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = "docs/continuous-fuzz-2026-11-15-43755401024-summary.json"
_SOURCE_COMMIT = "9deacd7ec0997fa2e3195729962d1fa52e10d271"
_WORKFLOW_RUN = 43755401024
_PLATFORMS = ("ubuntu", "macos", "windows")
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
_CASES_PER_TARGET = 5000
_TARGET_RUNS_PER_PLATFORM = 50000
_TOTAL_TARGET_RUNS = 150000
_EXPECTED_MACHO_WARNINGS = 103


def _summary() -> dict[str, object]:
    return json.loads((_ROOT / _SUMMARY_PATH).read_text(encoding="utf-8"))


def test_continuous_fuzz_manifest_binds_the_source_commit_and_workflow() -> None:
    summary = _summary()

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_run"] == _WORKFLOW_RUN
        and set(summary["platforms"]) == set(_PLATFORMS)
    )


def test_continuous_fuzz_reports_cover_all_targets_without_failures() -> None:
    summary = _summary()
    platforms = summary["platforms"]

    expect(
        all(
            platforms[name]["cases"] == _CASES_PER_TARGET
            and platforms[name]["failure_count"] == 0
            and set(platforms[name]["target_runs"]) == set(_EXPECTED_TARGETS)
            and sum(platforms[name]["target_runs"].values()) == _TARGET_RUNS_PER_PLATFORM
            and all(value == _CASES_PER_TARGET for value in platforms[name]["target_runs"].values())
            for name in _PLATFORMS
        )
        and summary["total_cases"] == _CASES_PER_TARGET * len(_PLATFORMS)
        and summary["total_failures"] == 0
        and summary["total_target_runs"] == _TOTAL_TARGET_RUNS
    )


def test_continuous_fuzz_report_hashes_match_archived_reports() -> None:
    platforms = _summary()["platforms"]

    expect(
        all(
            hashlib.sha256((_ROOT / platforms[name]["report"]).read_bytes()).hexdigest() == platforms[name]["sha256"]
            for name in _PLATFORMS
        )
    )


def test_continuous_fuzz_retains_parser_warnings_and_scope_limitations() -> None:
    summary = _summary()
    platforms = summary["platforms"]

    expect(
        all(
            platforms[name]["parser_diagnostic_counts"] == {"macho_load_commands.warning": _EXPECTED_MACHO_WARNINGS}
            for name in _PLATFORMS
        )
        and "Bounded deterministic fuzzing does not prove arbitrary-input semantic equivalence."
        in summary["limitations"]
        and "This fuzz campaign does not establish cross-platform behavioral parity or adversarial resistance."
        in summary["limitations"]
    )
