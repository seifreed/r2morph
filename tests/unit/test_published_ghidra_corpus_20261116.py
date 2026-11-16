"""Verify the bounded local Ghidra corpus evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/protection-ghidra-corpus-2026-11-16-981a45be.json"
_SUMMARY_PATH = _ROOT / "docs/protection-ghidra-corpus-2026-11-16-981a45be-summary.json"
_READINESS_PATH = _ROOT / "docs/one-zero-readiness.json"
_RAW_REPORT_SHA256 = "3e13c41b393ab10a2653d66a088eb7d1d4c7c32ee11b34e9f5eadfb986ad928b"
_SAMPLE_COUNT = 162
_ANALYSIS_RUN_COUNT = 324


def _report() -> dict[str, object]:
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def test_published_ghidra_summary_hash_matches_raw_report() -> None:
    summary = _summary()
    artifact = summary["raw_report"]
    digest = hashlib.sha256(_REPORT_PATH.read_bytes()).hexdigest()

    expect(
        artifact["path"] == "docs/protection-ghidra-corpus-2026-11-16-981a45be.json"
        and artifact["sha256"] == _RAW_REPORT_SHA256
        and artifact["sha256"] == digest
        and artifact["bytes"] == _REPORT_PATH.stat().st_size
    )


def test_published_ghidra_corpus_all_sample_pairs_are_complete() -> None:
    report = _report()
    samples = report["samples"]
    completed_pairs = sum(
        1
        for sample in samples
        for tool in sample["tools"]
        if tool["tool"] == "ghidra" and tool["status"] == "completed"
    )

    expect(
        report["sample_count"] == _SAMPLE_COUNT
        and len(samples) == _SAMPLE_COUNT
        and completed_pairs == _SAMPLE_COUNT
        and report["summary"]
        == {
            "completed_analysis_runs": _ANALYSIS_RUN_COUNT,
            "error_analysis_runs": 0,
            "timeout_analysis_runs": 0,
        }
    )


def test_published_ghidra_corpus_reports_only_virtualization_scope() -> None:
    report = _report()
    summary = report["pass_summary"]

    expect(
        set(summary) == {"CodeVirtualization"}
        and summary["CodeVirtualization"]["samples"] == _SAMPLE_COUNT
        and summary["CodeVirtualization"]["applied"] == _SAMPLE_COUNT
        and summary["CodeVirtualization"]["errors"] == 0
        and summary["CodeVirtualization"]["omitted"] == 0
        and _summary()["status"] == "bounded_partial"
    )


def test_published_ghidra_report_contains_no_host_paths() -> None:
    serialized = json.dumps(_report(), sort_keys=True)

    expect(re.search(r"/(?:Users|home|var/folders|tmp)/", serialized) is None)


def test_published_ghidra_evidence_preserves_open_release_gates() -> None:
    readiness = json.loads(_READINESS_PATH.read_text(encoding="utf-8"))
    criteria = readiness["criteria"]
    analyzer = criteria["all_named_adversarial_analyzers"]
    evidence = analyzer["evidence"]

    expect(
        readiness["status"] == "blocked"
        and analyzer["status"] == "open"
        and _REPORT_PATH.relative_to(_ROOT).as_posix() in evidence
        and _SUMMARY_PATH.relative_to(_ROOT).as_posix() in evidence
        and criteria["cross_platform_parity"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
    )
