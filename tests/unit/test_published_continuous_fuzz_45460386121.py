"""Pin the current-source three-platform continuous-fuzz campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/continuous-fuzz-2026-11-24-45460386121-summary.json"
_SOURCE_PATH = _ROOT / "scripts/continuous_fuzz.py"
_SOURCE_COMMIT = "92ff809ca8eecf9705189bb9728539365770d32b"
_SOURCE_SCRIPT_SHA256 = "471b130d72db7c6d643c3c856931181ad61c240ef9c621e9e82b1c98a99198fa"
_WORKFLOW_RUN = 45460386121
_CASES_PER_TARGET = 5000
_TARGET_RUNS_PER_PLATFORM = 50000
_TOTAL_TARGET_RUNS = 150000
_MAX_PAYLOAD_BYTES = 4096
_SEED = 20260827
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
_EXPECTED_PLATFORMS = {
    "macos-15": {
        "artifact_archive_sha256": "sha256:2713ac4c81b061274a0d59ea18b0f75dc09134e5708d5d02ccce2bf96a87e267",
        "artifact_id": 14952259681,
        "report_sha256": "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
        "report": "docs/continuous-fuzz-2026-11-24-45460386121-macos-15.json",
    },
    "ubuntu-latest": {
        "artifact_archive_sha256": "sha256:b872438318af304064d3e09b4c55ce01d4c0384e61a012bdf75449739db4a9a9",
        "artifact_id": 14951274405,
        "report_sha256": "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
        "report": "docs/continuous-fuzz-2026-11-24-45460386121-ubuntu-latest.json",
    },
    "windows-latest": {
        "artifact_archive_sha256": "sha256:221732698df8cfad82bb6b532cdd5c36f5b22ec3ebe4e0ef8fa8831e20fa973f",
        "artifact_id": 14952014794,
        "report_sha256": "03cdcbe0b6a4fe2a373d605ba4bc1ed40d669674ba30614feb61988b7a1bd21c",
        "report": "docs/continuous-fuzz-2026-11-24-45460386121-windows-latest.json",
    },
}
_REQUIRED_LIMITS = (
    "semantic equivalence",
    "complete product parity",
    "exhaustive fuzz coverage",
    "adversarial-resistance gates",
)


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def test_workflow_manifest_binds_source_commit_and_artifacts() -> None:
    summary = _summary()
    workflow = summary["workflow"]

    expect(
        workflow["run_id"] == _WORKFLOW_RUN
        and workflow["event"] == "push"
        and workflow["status"] == "success"
        and workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["url"] == "https://github.com/seifreed/r2morph/actions/runs/45460386121"
        and summary["configuration"]["source_script_sha256"]
        == hashlib.sha256(_SOURCE_PATH.read_bytes()).hexdigest()
        == _SOURCE_SCRIPT_SHA256
    )


def test_platform_reports_match_workflow_artifacts_and_campaign_scope() -> None:
    summary = _summary()
    configuration = summary["configuration"]
    execution = summary["execution"]
    platforms = execution["platforms"]

    expect(
        set(platforms) == set(_EXPECTED_PLATFORMS)
        and set(configuration["targets"]) == _EXPECTED_TARGETS
        and configuration["cases_per_target_per_platform"] == _CASES_PER_TARGET
        and configuration["seed"] == _SEED
        and configuration["max_payload_bytes"] == _MAX_PAYLOAD_BYTES
        and execution["total_target_runs"] == _TOTAL_TARGET_RUNS
        and execution["total_failures"] == 0
    )
    for platform, expected in _EXPECTED_PLATFORMS.items():
        platform_summary = platforms[platform]
        report_path = _ROOT / expected["report"]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()

        expect(
            platform_summary["artifact_id"] == expected["artifact_id"]
            and platform_summary["artifact_archive_sha256"] == expected["artifact_archive_sha256"]
            and platform_summary["report"] == expected["report"]
            and platform_summary["report_sha256"] == report_hash == expected["report_sha256"]
            and platform_summary["target_runs"] == _TARGET_RUNS_PER_PLATFORM
            and platform_summary["failure_count"] == 0
            and report["cases"] == _CASES_PER_TARGET
            and report["seed"] == _SEED
            and report["failure_count"] == 0
            and set(report["target_runs"]) == _EXPECTED_TARGETS
            and all(report["target_runs"][target] == _CASES_PER_TARGET for target in _EXPECTED_TARGETS)
            and sum(report["target_runs"].values()) == _TARGET_RUNS_PER_PLATFORM
            and report["parser_diagnostic_counts"] == platform_summary["parser_diagnostic_counts"]
        )


def test_manifest_states_campaign_limits_without_overclaiming() -> None:
    summary = _summary()
    limits = " ".join(summary["limits"])

    expect(all(limit in limits for limit in _REQUIRED_LIMITS))
