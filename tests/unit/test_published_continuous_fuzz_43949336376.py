"""Pin the cross-platform continuous fuzz reports to their source and run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/continuous-fuzz-2026-11-16-43949336376-summary.json"
_SOURCE_COMMIT = "6c60d58d186fc7725465313b79ce488dee1ee0c4"
_WORKFLOW_RUN = 43949336376
_EXPECTED_PLATFORMS = {"macos", "ubuntu", "windows"}
_EXPECTED_RUNNERS = {"macos-15", "ubuntu-latest", "windows-latest"}
_EXPECTED_TARGETS = {
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
}
_CASES_PER_TARGET = 5_000
_TARGETS_PER_PLATFORM = 10
_TOTAL_TARGET_RUNS = 150_000
_MACHO_DIAGNOSTICS = 103
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_published_continuous_fuzz_reports_match_source_and_hashes() -> None:
    summary = _json(_SUMMARY_PATH)
    platforms = summary["platforms"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_run"] == _WORKFLOW_RUN
        and summary["provenance"] == "github-actions-installed-wheel"
        and set(platforms) == _EXPECTED_PLATFORMS
        and {row["runner"] for row in platforms.values()} == _EXPECTED_RUNNERS
        and all(
            hashlib.sha256((_ROOT / platform["report"]).read_bytes()).hexdigest() == platform["sha256"]
            for platform in platforms.values()
        )
    )


def test_published_continuous_fuzz_reports_cover_each_target_without_failures() -> None:
    summary = _json(_SUMMARY_PATH)
    platforms = summary["platforms"]

    expect(
        all(
            row["cases"] == _CASES_PER_TARGET
            and row["failure_count"] == 0
            and set(row["target_runs"]) == _EXPECTED_TARGETS
            and all(count == _CASES_PER_TARGET for count in row["target_runs"].values())
            and sum(row["target_runs"].values()) == _CASES_PER_TARGET * _TARGETS_PER_PLATFORM
            for row in platforms.values()
        )
        and summary["total_cases"] == _CASES_PER_TARGET * len(_EXPECTED_PLATFORMS)
        and summary["total_failures"] == 0
        and summary["total_target_runs"] == _TOTAL_TARGET_RUNS
    )


def test_published_continuous_fuzz_reports_retain_parser_diagnostics() -> None:
    summary = _json(_SUMMARY_PATH)

    expect(
        all(
            row["parser_diagnostic_counts"] == {"macho_load_commands.warning": _MACHO_DIAGNOSTICS}
            for row in summary["platforms"].values()
        )
        and any("does not prove arbitrary-input semantic equivalence" in item for item in summary["limitations"])
    )


def test_published_continuous_fuzz_reports_do_not_expose_host_paths() -> None:
    summary = _json(_SUMMARY_PATH)
    reports = [_SUMMARY_PATH.read_text(encoding="utf-8")]
    reports.extend((_ROOT / row["report"]).read_text(encoding="utf-8") for row in summary["platforms"].values())

    expect(not any(prefix in "".join(reports) for prefix in _HOST_PATH_PREFIXES))
