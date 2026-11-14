"""Regression checks for the bounded local IDA campaign evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_RAW_REPORT = _ROOT / "docs" / "protection-adversarial-local-ida-2026-11-14-1946be26.json"
_SUMMARY = _ROOT / "docs" / "protection-adversarial-local-ida-2026-11-14-1946be26-summary.json"
_READINESS = _ROOT / "docs" / "one-zero-readiness.json"
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")


def test_local_ida_summary_binds_to_raw_campaign_report() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == "1946be26"
        and summary["provenance"] == "local-source-tree"
        and summary["report_sha256"] == hashlib.sha256(_RAW_REPORT.read_bytes()).hexdigest()
    )


def test_local_ida_campaign_applies_virtualization_and_records_decompiler_delta() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))

    expect(
        summary["fixture"] == "elf_vm_arith_x86_64"
        and summary["pass"]
        == {
            "name": "CodeVirtualization",
            "status": "applied",
            "functions_virtualized": 1,
            "partial_virtualization": 0,
            "unsupported_functions": 0,
        }
        and summary["ida_pro"]
        == {
            "status": "completed",
            "functions_delta": 1,
            "decompiler_lines_delta": 26,
            "decompiler_bytes_delta": 939,
        }
    )


def test_local_ida_campaign_keeps_unavailable_analyzers_and_release_gate_open() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))

    expect(
        summary["tool_statuses"]["ida-pro"] == "completed"
        and summary["tool_statuses"]["binary-ninja"] == "unavailable"
        and summary["tool_statuses"]["ghidra"] == "unavailable"
        and summary["tool_statuses"]["triton"] == "unavailable"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_local_ida_campaign_does_not_expose_analyst_paths() -> None:
    report_text = _RAW_REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(prefix in report_text for prefix in _HOST_PATH_PREFIXES))
