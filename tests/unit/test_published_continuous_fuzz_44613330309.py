"""Pin the current-main continuous-fuzz run to its workflow reports."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = "docs/continuous-fuzz-2026-11-19-44613330309-summary.json"
_SOURCE_COMMIT = "b561237880a5b42bd45494424fbd291ae832dfc7"
_WORKFLOW_RUN = 44613330309
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
_TARGET_RUNS_PER_PLATFORM = 50000
_TOTAL_TARGET_RUNS = 150000
_EXPECTED_DIAGNOSTICS = {"macho_load_commands.warning": 101}
_UNPROVEN_SCOPE = (
    "This deterministic harness run covers bounded generated parser, assembler, VM, relocation, and rewrite inputs; "
    "it does not prove semantic equivalence for arbitrary transformed binaries."
)


def _summary() -> dict[str, object]:
    return json.loads((_ROOT / _SUMMARY_PATH).read_text(encoding="utf-8"))


def test_manifest_binds_fuzz_reports_to_current_source_and_workflow() -> None:
    summary = _summary()
    workflow = summary["workflow"]

    expect(
        workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["run_id"] == _WORKFLOW_RUN
        and workflow["status"] == "success"
        and set(summary["execution"]["platforms"]) == set(_PLATFORMS)
    )


def test_fuzz_reports_cover_every_target_without_failures() -> None:
    summary = _summary()
    configuration = summary["configuration"]
    execution = summary["execution"]

    expect(
        set(configuration["targets"]) == _EXPECTED_TARGETS
        and configuration["cases_per_target_per_platform"] == _CASES_PER_TARGET
        and all(
            execution["platforms"][platform]["target_runs"] == _TARGET_RUNS_PER_PLATFORM
            and execution["platforms"][platform]["failure_count"] == 0
            and execution["platforms"][platform]["parser_diagnostic_counts"] == _EXPECTED_DIAGNOSTICS
            for platform in _PLATFORMS
        )
        and execution["total_target_runs"] == _TOTAL_TARGET_RUNS
        and execution["total_failures"] == 0
    )


def test_archived_fuzz_reports_match_workflow_artifact_hashes() -> None:
    platforms = _summary()["execution"]["platforms"]

    expect(
        all(
            hashlib.sha256(gzip.decompress((_ROOT / platforms[platform]["report"]).read_bytes())).hexdigest()
            == platforms[platform]["report_sha256"]
            == platforms[platform]["workflow_artifact_sha256"]
            for platform in _PLATFORMS
        )
    )


def test_campaign_limits_and_source_script_hash_are_explicit() -> None:
    summary = _summary()
    configuration = summary["configuration"]
    script_hash = hashlib.sha256((_ROOT / configuration["source_script"]).read_bytes()).hexdigest()

    expect(
        configuration["max_payload_bytes"] == _MAX_PAYLOAD_BYTES
        and script_hash == configuration["source_script_sha256"]
        and _UNPROVEN_SCOPE in summary["limits"]
    )
