"""Verify the current-source bounded Ghidra corpus evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/protection-ghidra-corpus-2026-11-20-716dcfac.json"
_SUMMARY_PATH = _ROOT / "docs/protection-ghidra-corpus-2026-11-20-716dcfac-summary.json"
_SCRIPT_PATH = _ROOT / "scripts/ghidra_corpus_benchmark.py"
_READINESS_PATH = _ROOT / "docs/one-zero-readiness.json"
_SOURCE_COMMIT = "716dcfac4df73eae11637f8ca7a9dab6e8f49dfc"
_RAW_REPORT_SHA256 = "a627c0cfb0f9aff632b8e5decda160fa6d1e2a6665011b0b0e62f0974ca9ad11"
_SCRIPT_SHA256 = "cb820592936e8299a5749affc12d85fa7d8666b474d9a016f9ae4f9bdeb53b5d"
_SAMPLE_COUNT = 162
_ANALYSIS_RUN_COUNT = 324
_FUNCTIONS_VIRTUALIZED = 170


def _report() -> dict[str, object]:
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def test_published_ghidra_summary_pins_report_and_benchmark_hashes() -> None:
    summary = _summary()
    raw_report = summary["raw_report"]

    expect(
        raw_report["path"] == "docs/protection-ghidra-corpus-2026-11-20-716dcfac.json"
        and raw_report["sha256"] == hashlib.sha256(_REPORT_PATH.read_bytes()).hexdigest() == _RAW_REPORT_SHA256
        and raw_report["bytes"] == _REPORT_PATH.stat().st_size
        and summary["benchmark_script_sha256"]
        == hashlib.sha256(_SCRIPT_PATH.read_bytes()).hexdigest()
        == _SCRIPT_SHA256
        and summary["source_commit"] == _SOURCE_COMMIT
        and summary["status"] == "bounded_partial"
    )


def test_published_ghidra_corpus_contains_all_completed_fixture_pairs() -> None:
    report = _report()
    samples = report["samples"]
    completed = [
        sample
        for sample in samples
        if sample["tools"][0]["tool"] == "ghidra" and sample["tools"][0]["status"] == "completed"
    ]

    expect(
        report["sample_count"] == _SAMPLE_COUNT
        and len(samples) == len(completed) == _SAMPLE_COUNT
        and report["summary"]
        == {
            "completed_analysis_runs": _ANALYSIS_RUN_COUNT,
            "error_analysis_runs": 0,
            "timeout_analysis_runs": 0,
        }
        and _summary()["analysis_runs"] == report["summary"]
    )


def test_published_ghidra_corpus_records_bounded_virtualization_observations() -> None:
    report = _report()
    comparison = _summary()["function_count_comparison"]
    pass_summary = report["pass_summary"]

    expect(
        comparison
        == {
            "changed_pairs": 151,
            "completed_pairs": _SAMPLE_COUNT,
            "original_functions_total": 206,
            "protected_functions_total": 388,
            "unchanged_pairs": 11,
        }
        and set(pass_summary) == {"CodeVirtualization"}
        and pass_summary["CodeVirtualization"]["samples"] == _SAMPLE_COUNT
        and pass_summary["CodeVirtualization"]["applied"] == _SAMPLE_COUNT
        and pass_summary["CodeVirtualization"]["functions_virtualized"] == _FUNCTIONS_VIRTUALIZED
        and pass_summary["CodeVirtualization"]["errors"] == 0
        and pass_summary["CodeVirtualization"]["unsupported_functions"] == 0
        and pass_summary["CodeVirtualization"]["partial_virtualization"] == 0
    )


def test_published_ghidra_evidence_keeps_release_gates_open() -> None:
    readiness = json.loads(_READINESS_PATH.read_text(encoding="utf-8"))
    criteria = readiness["criteria"]
    analyzer_evidence = criteria["all_named_adversarial_analyzers"]["evidence"]

    expect(
        readiness["status"] == "blocked"
        and criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["cross_platform_parity"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and _REPORT_PATH.relative_to(_ROOT).as_posix() in analyzer_evidence
        and _SUMMARY_PATH.relative_to(_ROOT).as_posix() in analyzer_evidence
    )


def test_published_ghidra_report_contains_no_host_paths() -> None:
    serialized = json.dumps(_report(), sort_keys=True)

    expect(re.search(r"/(?:Users|home|var/folders|tmp)/", serialized) is None)
