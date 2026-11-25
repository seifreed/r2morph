"""Pin bounded local continuous-fuzz evidence to its source and report."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/continuous-fuzz-local-2026-11-24-92ff809c.json"
_REPORT_PATH = _ROOT / "docs/continuous-fuzz-local-2026-11-24-92ff809c-report.json"
_SOURCE_COMMIT = "92ff809ca8eecf9705189bb9728539365770d32b"
_SOURCE_SCRIPT_SHA256 = "471b130d72db7c6d643c3c856931181ad61c240ef9c621e9e82b1c98a99198fa"
_REPORT_SHA256 = "3a55ae6eb3246eed59348adb1036e68d18683500912426bb2d38784dbfdebce7"
_CASE_COUNT = 5000
_SEED = 20261124
_TOTAL_TARGET_RUNS = 50000
_MAX_PAYLOAD_BYTES = 4096
_REQUIRED_LIMITATIONS = (
    "semantic equivalence",
    "cross-platform parity",
    "exhaustive fuzz coverage",
    "adversarial resistance",
)
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


def test_local_campaign_binds_report_and_script_hashes() -> None:
    summary = json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["report_sha256"] == hashlib.sha256(_REPORT_PATH.read_bytes()).hexdigest() == _REPORT_SHA256
        and summary["source_script_sha256"] == _SOURCE_SCRIPT_SHA256
    )


def test_local_campaign_covers_declared_targets_without_failures() -> None:
    summary = json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))
    report = json.loads(_REPORT_PATH.read_text(encoding="utf-8"))

    expect(
        summary["cases"] == report["cases"] == _CASE_COUNT
        and summary["seed"] == report["seed"] == _SEED
        and summary["failure_count"] == report["failure_count"] == 0
        and summary["max_payload_bytes"] == report["max_payload"] == _MAX_PAYLOAD_BYTES
        and set(report["target_runs"]) == _EXPECTED_TARGETS
        and all(report["target_runs"][target] == _CASE_COUNT for target in _EXPECTED_TARGETS)
        and sum(report["target_runs"].values()) == summary["total_target_runs"] == _TOTAL_TARGET_RUNS
        and summary["parser_diagnostic_counts"] == report["parser_diagnostic_counts"]
        and summary["runtime"]["architecture"] == "arm64"
        and summary["runtime"]["operating_system"] == "Darwin"
        and summary["runtime"]["python"] == "3.13.17"
        and summary["runtime"]["keystone"] == "0.9.2"
        and all(term in " ".join(summary["limitations"]) for term in _REQUIRED_LIMITATIONS)
    )
