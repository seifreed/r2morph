"""Checks hash-bound, cross-platform continuous fuzz evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-fuzz-continuous-run-2026-11-14-43631586471.json"
_SOURCE_COMMIT = "350c0d79b6ff2ae712b4fe26f7abd1654ed3467e"
_SCOPE_COMMIT = "8403661b"
_WORKFLOW_RUN = 43_631_586_471
_PLATFORMS = ("ubuntu-latest", "macos-15", "windows-latest")
_FUZZ_TARGETS = (
    "assembling",
    "binary_parsers",
    "elf_header_parser",
    "pe_header_parser",
    "macho_load_commands",
    "vm_dispatcher",
    "vm_bytecode",
    "vm_instruction_decoder",
    "relocations",
    "binary_rewriter",
)
_CASES_PER_TARGET = 5_000
_EXPECTED_TARGET_RUNS = 50_000
_EXPECTED_TOTAL_RUNS = 150_000
_MAX_PAYLOAD_BYTES = 4_096
_MACHO_WARNING_COUNT = 103
_HOST_PATH_MARKERS = (b"/Users/", b"/home/", b"/tmp/", b"/private/tmp/", b"C:\\Users\\")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def test_fuzz_run_reports_match_hash_bound_artifacts() -> None:
    summary = _summary()

    expect(
        summary["workflow"]["run_id"] == _WORKFLOW_RUN
        and summary["source_commit"] == _SOURCE_COMMIT
        and summary["scope_commit"] == _SCOPE_COMMIT
        and summary["fuzz_scope_unchanged_since_source_commit"] is True
        and all(
            platform["sha256"] == hashlib.sha256((_ROOT / "docs" / platform["report"]).read_bytes()).hexdigest()
            and platform["size_bytes"] == (_ROOT / "docs" / platform["report"]).stat().st_size
            for platform in summary["platforms"].values()
        )
    )


def test_fuzz_run_covers_all_targets_on_three_platforms_without_failures() -> None:
    summary = _summary()

    expect(
        summary["workflow"]["status"] == "completed"
        and summary["workflow"]["conclusion"] == "success"
        and summary["workflow"]["successful_platform_jobs"] == len(_PLATFORMS)
        and summary["workflow"]["total_platform_jobs"] == len(_PLATFORMS)
        and summary["scope"]["cases_per_platform"] == _CASES_PER_TARGET
        and summary["scope"]["max_payload_bytes"] == _MAX_PAYLOAD_BYTES
        and summary["scope"]["targets"] == list(_FUZZ_TARGETS)
        and summary["scope"]["target_runs_per_platform"] == _EXPECTED_TARGET_RUNS
        and summary["scope"]["total_target_runs"] == _EXPECTED_TOTAL_RUNS
        and all(
            platform["failure_count"] == 0
            and platform["seed"] == summary["scope"]["seed"]
            and platform["cases"] == _CASES_PER_TARGET
            and platform["max_payload"] == _MAX_PAYLOAD_BYTES
            and platform["target_runs"] == dict.fromkeys(_FUZZ_TARGETS, _CASES_PER_TARGET)
            and platform["parser_diagnostic_counts"] == {"macho_load_commands.warning": _MACHO_WARNING_COUNT}
            for platform in summary["platforms"].values()
        )
        and set(summary["platforms"]) == set(_PLATFORMS)
    )


def test_fuzz_reports_do_not_disclose_host_paths() -> None:
    summary = _summary()
    report_paths = [_ROOT / "docs" / platform["report"] for platform in summary["platforms"].values()]
    published_bytes = _SUMMARY_PATH.read_bytes() + b"".join(path.read_bytes() for path in report_paths)

    expect(not any(marker in published_bytes for marker in _HOST_PATH_MARKERS))
