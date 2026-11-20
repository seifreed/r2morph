"""Pin the current-main continuous-fuzz run to its workflow reports."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = "docs/continuous-fuzz-2026-11-19-44631018926-summary.json"
_SOURCE_COMMIT = "d363ed864baed45e180e0ba8a05403a0e1f508d7"
_SOURCE_SCRIPT_SHA256 = "6bf18f8c3d62906ab4cd571db492ef3cb3367481d2c752a487f2ed027c7c7bc8"
_WORKFLOW_RUN = 44_631_018_926
_PLATFORMS = ("ubuntu-latest", "macos-15", "windows-latest")
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
_CASES_PER_TARGET = 5000
_MAX_PAYLOAD_BYTES = 4096
_SEED = 20260827
_TARGET_RUNS_PER_PLATFORM = 50000
_TOTAL_TARGET_RUNS = 150000
_EXPECTED_DIAGNOSTICS = {"macho_load_commands.warning": 103}


def _summary() -> dict[str, object]:
    return json.loads((_ROOT / _SUMMARY_PATH).read_text(encoding="utf-8"))


def _report(platform: str) -> tuple[bytes, dict[str, object]]:
    entry = _summary()["execution"]["platforms"][platform]
    raw = gzip.decompress((_ROOT / entry["report"]).read_bytes())
    return raw, json.loads(raw)


def test_manifest_binds_fuzz_reports_to_current_source_and_workflow() -> None:
    summary = _summary()
    workflow = summary["workflow"]
    configuration = summary["configuration"]

    expect(
        workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["run_id"] == _WORKFLOW_RUN
        and workflow["status"] == "success"
        and set(summary["execution"]["platforms"]) == set(_PLATFORMS)
        and configuration["source_script_sha256"] == _SOURCE_SCRIPT_SHA256
    )


def test_fuzz_reports_cover_all_targets_without_failures() -> None:
    summary = _summary()
    configuration = summary["configuration"]
    execution = summary["execution"]

    expect(
        set(configuration["targets"]) == _EXPECTED_TARGETS
        and configuration["cases_per_target_per_platform"] == _CASES_PER_TARGET
        and execution["total_target_runs"] == _TOTAL_TARGET_RUNS
        and execution["total_failures"] == 0
        and all(
            execution["platforms"][platform]["target_runs"] == _TARGET_RUNS_PER_PLATFORM
            and execution["platforms"][platform]["failure_count"] == 0
            and execution["platforms"][platform]["parser_diagnostic_counts"] == _EXPECTED_DIAGNOSTICS
            for platform in _PLATFORMS
        )
    )


def test_archived_reports_match_artifact_hashes_and_campaign_results() -> None:
    platforms = _summary()["execution"]["platforms"]

    expect(
        all(
            hashlib.sha256(raw).hexdigest()
            == platforms[platform]["report_sha256"]
            == platforms[platform]["workflow_artifact_sha256"]
            and report["seed"] == _SEED
            and report["cases"] == _CASES_PER_TARGET
            and report["failure_count"] == 0
            and report["max_payload"] == _MAX_PAYLOAD_BYTES
            and set(report["target_runs"]) == _EXPECTED_TARGETS
            and set(report["target_runs"].values()) == {_CASES_PER_TARGET}
            and report["parser_diagnostic_counts"] == _EXPECTED_DIAGNOSTICS
            for platform in _PLATFORMS
            for raw, report in [_report(platform)]
        )
    )
