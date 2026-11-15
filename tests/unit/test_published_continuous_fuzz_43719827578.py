"""Pin cross-platform fuzz campaign evidence to its source and reports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = "docs/continuous-fuzz-2026-11-15-43719827578-summary.json"
_SOURCE_COMMIT = "ec0cfa8e51d186eaa1e2fff64f7242b2fe2ee3d7"
_WORKFLOW_RUN = 43719827578
_EXPECTED_PLATFORMS = ("ubuntu", "macos", "windows")
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
_CASES_PER_PLATFORM = 5000
_RUNS_PER_PLATFORM = 50000
_TOTAL_TARGET_RUNS = 150000
_EXPECTED_MACHO_DIAGNOSTICS = 103
_WINDOWS_SOURCE_SHA256 = "03cdcbe0b6a4fe2a373d605ba4bc1ed40d669674ba30614feb61988b7a1bd21c"
_ZERO = 0


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_continuous_fuzz_reports_match_source_and_hashes() -> None:
    summary = _json(_ROOT / _SUMMARY_PATH)
    platforms = summary["platforms"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_run"] == _WORKFLOW_RUN
        and set(platforms) == set(_EXPECTED_PLATFORMS)
        and platforms["windows"]["source_sha256"] == _WINDOWS_SOURCE_SHA256
        and all(
            hashlib.sha256((_ROOT / platforms[name]["report"]).read_bytes()).hexdigest() == platforms[name]["sha256"]
            for name in _EXPECTED_PLATFORMS
        )
    )


def test_continuous_fuzz_campaign_covers_all_targets_without_failures() -> None:
    summary = _json(_ROOT / _SUMMARY_PATH)
    platforms = summary["platforms"]

    expect(
        all(
            platforms[name]["cases"] == _CASES_PER_PLATFORM
            and platforms[name]["failure_count"] == _ZERO
            and set(platforms[name]["target_runs"]) == set(_EXPECTED_TARGETS)
            and sum(platforms[name]["target_runs"].values()) == _RUNS_PER_PLATFORM
            and all(platforms[name]["target_runs"][target] == _CASES_PER_PLATFORM for target in _EXPECTED_TARGETS)
            for name in _EXPECTED_PLATFORMS
        )
        and summary["total_cases"] == _CASES_PER_PLATFORM * len(_EXPECTED_PLATFORMS)
        and summary["total_target_runs"] == _TOTAL_TARGET_RUNS
        and summary["total_failures"] == _ZERO
    )


def test_continuous_fuzz_warnings_remain_visible_in_evidence() -> None:
    summary = _json(_ROOT / _SUMMARY_PATH)
    platforms = summary["platforms"]

    expect(
        all(
            platforms[name]["parser_diagnostic_counts"] == {"macho_load_commands.warning": _EXPECTED_MACHO_DIAGNOSTICS}
            for name in _EXPECTED_PLATFORMS
        )
        and any(
            item == "Bounded deterministic fuzzing does not prove arbitrary-input semantic equivalence."
            for item in summary["limitations"]
        )
    )
