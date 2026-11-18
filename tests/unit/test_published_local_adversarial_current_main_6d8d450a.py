"""Verify the hash-bound current-source local IDA sample measurement."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/protection-adversarial-current-main-local-2026-11-18-6d8d450a.json"
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-current-main-local-2026-11-18-6d8d450a-summary.json"
_FIXTURE_PATH = _ROOT / "fixtures/dataset/elf_vm_arith_x86_64"
_SOURCE_COMMIT = "6d8d450a2cabe27fdfa723b7d911ce9a5a15f35c"
_REPORT_SHA256 = "84da2761a37fbab64dc473e89fc530fd89fcbd2a29787c5494d271ea9f35dd4f"
_FIXTURE_SHA256 = "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00"
_APPLIED = "applied"
_EXPECTED_SAMPLE_COUNT = 1
_EXPECTED_VIRTUALIZED_FUNCTIONS = 1
_EXPECTED_TOOL_RUNS = 9
_COMPLETED_TOOL_RUNS = 6
_UNAVAILABLE_TOOL_RUNS = 3
_ZERO = 0
_HOST_PATH = re.compile(rb"(?:/(?:Users|Applications|private|tmp|home|root|workspace)/|[A-Za-z]:\\Users\\)")


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY_PATH.read_text(encoding="utf-8")))


def _report() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_REPORT_PATH.read_text(encoding="utf-8")))


def test_current_source_local_report_is_bound_to_commit_and_fixture() -> None:
    summary = _summary()

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_report_sha256"] == _REPORT_SHA256
        and hashlib.sha256(_REPORT_PATH.read_bytes()).hexdigest() == _REPORT_SHA256
        and summary["fixture"]["sha256"] == _FIXTURE_SHA256
        and hashlib.sha256(_FIXTURE_PATH.read_bytes()).hexdigest() == _FIXTURE_SHA256
    )


def test_current_source_local_report_records_applied_virtualization() -> None:
    scope = _summary()["scope"]
    pass_status = scope["pass_status"]

    expect(
        scope["samples"] == _EXPECTED_SAMPLE_COUNT
        and scope["passes"] == ["CodeVirtualization"]
        and pass_status == _APPLIED
        and scope["functions_virtualized"] == _EXPECTED_VIRTUALIZED_FUNCTIONS
        and scope["partial_virtualization"] == scope["unsupported_functions"] == _ZERO
    )


def test_current_source_local_report_records_completed_ida_decompilation() -> None:
    ida = next(tool for tool in _report()["tools"] if tool["tool"] == "ida-pro")

    expect(ida["original"]["decompiler_status"] == ida["protected"]["decompiler_status"] == "completed")


def test_current_source_local_report_keeps_unavailable_analyzers_explicit() -> None:
    scope = _summary()["scope"]

    expect(
        scope["expected_tool_runs"] == _EXPECTED_TOOL_RUNS
        and scope["completed_tool_runs"] == _COMPLETED_TOOL_RUNS
        and scope["unavailable_tool_runs"] == _UNAVAILABLE_TOOL_RUNS
        and scope["error_tool_runs"] == scope["missing_tool_runs"] == _ZERO
        and scope["unavailable_reasons_by_tool"]["binary-ninja"] == {"analyzer license is unavailable": 1}
    )


def test_current_source_local_report_keeps_readiness_gates_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    analyzers = readiness["criteria"]["all_named_adversarial_analyzers"]

    expect(
        analyzers["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _REPORT_PATH.relative_to(_ROOT).as_posix() in analyzers["evidence"]
        and _SUMMARY_PATH.relative_to(_ROOT).as_posix() in analyzers["evidence"]
    )


def test_current_source_local_report_contains_no_host_paths() -> None:
    expect(_HOST_PATH.search(_REPORT_PATH.read_bytes() + _SUMMARY_PATH.read_bytes()) is None)
