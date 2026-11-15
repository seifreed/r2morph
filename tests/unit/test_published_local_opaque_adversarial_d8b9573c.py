"""Pin the bounded local analyzer evidence for opaque predicates."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = "docs/protection-adversarial-local-opaque-2026-11-15-d8b9573c-summary.json"
_REPORT_PATH = "docs/protection-adversarial-local-opaque-2026-11-15-d8b9573c.json"
_SOURCE_COMMIT = "d8b9573cfc985fd499db05aa904beb6a7c508a3c"
_REPORT_SHA256 = "6f41d0557d3ca02fe36d3dbbceea7d293b8390e57032f9a41c0579b00853028d"
_MUTATION_FIELD = "pass"
_EXPECTED_MUTATION_NAME = "OpaquePredicates"
_MUTATION_COUNT = 13
_EXPECTED_TOOL_SLOTS = 9
_COMPLETED_TOOL_SLOTS = 4
_UNAVAILABLE_TOOL_SLOTS = 5
_ERROR_TOOL_SLOTS = 0
_TEMP_PATH_MARKER = f"{os.sep}tmp{os.sep}"


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_local_opaque_adversarial_manifest_binds_source_and_report() -> None:
    summary = _json(_ROOT / _SUMMARY_PATH)
    report = summary["report"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and report["path"] == _REPORT_PATH
        and report["sha256"] == _REPORT_SHA256
        and hashlib.sha256((_ROOT / _REPORT_PATH).read_bytes()).hexdigest() == _REPORT_SHA256
    )


def test_local_opaque_adversarial_report_records_applied_pass() -> None:
    summary = _json(_ROOT / _SUMMARY_PATH)
    fixture = summary["fixture"]
    report = _json(_ROOT / _REPORT_PATH)
    sample = report["samples"][0]
    pass_row = sample["passes"][0]

    expect(
        fixture["name"] == "generated_cpp_exceptions_clangxx-static-o2"
        and fixture[_MUTATION_FIELD] == _EXPECTED_MUTATION_NAME
        and fixture["mutations_applied"] == _MUTATION_COUNT
        and pass_row["status"] == "applied"
        and pass_row["mutations_applied"] == _MUTATION_COUNT
        and fixture["protected_sha256"] == "67b3f6ab6ea017381dde85a13090d6fefe95ba4868ac98dea2aff1a5d87c2d45"
    )


def test_local_opaque_adversarial_report_accounts_for_all_analyzer_slots() -> None:
    summary = _json(_ROOT / _SUMMARY_PATH)
    measurement = summary["measurement"]

    expect(
        measurement["expected_tool_slots"] == _EXPECTED_TOOL_SLOTS
        and measurement["completed_tool_slots"] == _COMPLETED_TOOL_SLOTS
        and measurement["unavailable_tool_slots"] == _UNAVAILABLE_TOOL_SLOTS
        and measurement["error_tool_slots"] == _ERROR_TOOL_SLOTS
        and set(measurement["completed_analyzers"]) == {"angr", "custom", "objdump", "radare2"}
    )


def test_local_opaque_adversarial_report_keeps_release_gate_open() -> None:
    readiness = _json(_ROOT / "docs/one-zero-readiness.json")
    evidence = readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
    report = (_ROOT / _REPORT_PATH).read_text(encoding="utf-8")

    expect(
        readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and _REPORT_PATH in evidence
        and _SUMMARY_PATH in evidence
        and "/Users/" not in report
        and _TEMP_PATH_MARKER not in report
    )
