"""Pin current-source cross-platform fuzz evidence to its workflow artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = "docs/continuous-fuzz-2026-11-20-44676210319-summary.json"
_SOURCE_COMMIT = "2f54c47ee08dee65a2aeda406ee4bd8a3a78bbfc"
_SOURCE_SCRIPT_SHA256 = "471b130d72db7c6d643c3c856931181ad61c240ef9c621e9e82b1c98a99198fa"
_WORKFLOW_RUN = 44_676_210_319
_SEED = 20_261_120
_CASES_PER_TARGET = 5_000
_MAX_PAYLOAD_BYTES = 4_096
_RUNS_PER_PLATFORM = 50_000
_TOTAL_TARGET_RUNS = 150_000
_PLATFORMS = {
    "macos-15": (
        14601583697,
        "sha256:9b3a4e5fadd7a95cab93c71a31b22fc8eec046ff3ac1df9399c5c9af4088a377",
        "0cf589a148aed51c2a01639ccdec48fdbd846b9d954dbea5ddd59cab084c0ef7",
    ),
    "ubuntu-latest": (
        14601683489,
        "sha256:850749601d5db53722865ae533bd7bdfadc7c6bf5c09a12b7459ccbdfebc5702",
        "0cf589a148aed51c2a01639ccdec48fdbd846b9d954dbea5ddd59cab084c0ef7",
    ),
    "windows-latest": (
        14602720084,
        "sha256:b6783972ef551240913c66938539f5400e79dd6c94921b01badb85075d9cdc05d",
        "afd916539196b2028661669293a52651026d337c89ae8802ba492ee26c6adcc7",
    ),
}
_TARGETS = {
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
_DIAGNOSTICS = {"macho_load_commands.warning": 96}


def _summary() -> dict[str, object]:
    return json.loads((_ROOT / _SUMMARY_PATH).read_text(encoding="utf-8"))


def test_manifest_binds_current_source_commit_and_workflow_run() -> None:
    summary = _summary()
    workflow = summary["workflow"]
    configuration = summary["configuration"]

    expect(
        workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["run_id"] == _WORKFLOW_RUN
        and workflow["status"] == "success"
        and hashlib.sha256((_ROOT / configuration["source_script"]).read_bytes()).hexdigest()
        == _SOURCE_SCRIPT_SHA256
        == configuration["source_script_sha256"]
    )


def test_reports_cover_all_targets_on_all_platforms_without_failures() -> None:
    summary = _summary()
    configuration = summary["configuration"]
    execution = summary["execution"]
    platforms = execution["platforms"]

    expect(
        configuration["cases_per_target_per_platform"] == _CASES_PER_TARGET
        and configuration["seed"] == _SEED
        and configuration["max_payload_bytes"] == _MAX_PAYLOAD_BYTES
        and set(configuration["targets"]) == _TARGETS
        and set(platforms) == set(_PLATFORMS)
        and execution["total_target_runs"] == _TOTAL_TARGET_RUNS
        and execution["total_failures"] == 0
    )
    for platform, (artifact_id, artifact_digest, report_digest) in _PLATFORMS.items():
        entry = platforms[platform]
        raw = (_ROOT / entry["report"]).read_bytes()
        report = json.loads(raw)
        expect(
            entry["artifact_id"] == artifact_id
            and entry["artifact_archive_sha256"] == artifact_digest
            and hashlib.sha256(raw).hexdigest() == report_digest == entry["report_sha256"]
            and entry["target_runs"] == _RUNS_PER_PLATFORM
            and entry["failure_count"] == 0
            and entry["parser_diagnostic_counts"] == _DIAGNOSTICS
            and report["seed"] == _SEED
            and report["cases"] == _CASES_PER_TARGET
            and report["max_payload"] == _MAX_PAYLOAD_BYTES
            and report["failure_count"] == 0
            and report["failures"] == []
            and set(report["target_runs"]) == _TARGETS
            and set(report["target_runs"].values()) == {_CASES_PER_TARGET}
        )


def test_limits_keep_equivalence_and_complete_platform_parity_open() -> None:
    limits = _summary()["limits"]

    expect(
        any("does not fuzz complete executable semantics" in limit for limit in limits)
        and any("does not establish exhaustive fuzz coverage or complete platform parity" in limit for limit in limits)
        and any(
            "does not close the open differential, compatibility, or adversarial-resistance gates" in limit
            for limit in limits
        )
    )
