"""Checks hash-bound current-main adversarial and VM resistance evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_ADVERSARIAL_SUMMARY = _ROOT / "docs/protection-adversarial-run-2026-11-14-43592902305.json"
_RESISTANCE_SUMMARY = _ROOT / "docs/protection-vm-resistance-run-2026-11-14-43592902305.json"
_LOCAL_SUMMARY = _ROOT / "docs/protection-adversarial-local-analyzer-2026-11-14-8ab01d2f-summary.json"
_SOURCE_COMMIT = "334f6626a38bfdbf933ecaf5afdc4312a6d61d98"
_LOCAL_SOURCE_COMMIT = "8ab01d2fac1e61f812252f37dc84fab54c1e8c2f"
_WORKFLOW_RUN = 43_592_902_305
_SAMPLE_COUNT = 362
_PASS_COUNT = 22
_EXPECTED_PASS_RUNS = 7_964
_UNAVAILABLE_TOOL_RUNS_PER_ANALYZER = 7_964
_RESISTANCE_FIXTURE_COUNT = 15
_RESISTANCE_SEED_COUNT = 10
_GROWTH_FIXTURE_COUNT = 6
_ZERO = 0
_CHUNK_BYTES = 1024 * 1024


def _summary(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _uncompressed_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = _ZERO
    with gzip.open(path, "rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
            byte_count += len(chunk)
    return digest.hexdigest(), byte_count


def test_adversarial_corpus_summary_binds_full_report_and_run() -> None:
    summary = _summary(_ADVERSARIAL_SUMMARY)
    report = _ROOT / "docs" / summary["report"]
    raw_digest, raw_bytes = _uncompressed_digest(report)

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow_run"] == _WORKFLOW_RUN
        and summary["report_sha256"] == _digest(report)
        and summary["uncompressed_report_sha256"] == raw_digest
        and summary["uncompressed_report_bytes"] == raw_bytes
    )


def test_adversarial_corpus_summary_retains_analyzer_gaps() -> None:
    summary = _summary(_ADVERSARIAL_SUMMARY)
    results = summary["results"]
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        summary["scope"]["samples"] == _SAMPLE_COUNT
        and summary["scope"]["passes"] == _PASS_COUNT
        and summary["scope"]["expected_pass_runs"] == _EXPECTED_PASS_RUNS
        and results["error_tool_runs"] == _ZERO
        and results["unavailable_tool_runs_by_tool"]["binary-ninja"] == _UNAVAILABLE_TOOL_RUNS_PER_ANALYZER
        and results["unavailable_tool_runs_by_tool"]["ida-pro"] == _UNAVAILABLE_TOOL_RUNS_PER_ANALYZER
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
    )


def test_vm_resistance_summary_binds_reports_and_leaves_human_review_open() -> None:
    summary = _summary(_RESISTANCE_SUMMARY)
    artifacts = summary["artifacts"]

    expect(
        all(
            artifact["report_sha256"] == _digest(_ROOT / "docs" / artifact["report"]) for artifact in artifacts.values()
        )
        and summary["measurement"]["fixture_count"] == _RESISTANCE_FIXTURE_COUNT
        and summary["measurement"]["seed_count"] == _RESISTANCE_SEED_COUNT
        and summary["measurement"]["progressive_growth_supported_fixture_count"] == _GROWTH_FIXTURE_COUNT
        and summary["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        and summary["readiness"]["published_resistance_results"] == "open"
    )


def test_local_ida_ghidra_campaign_binds_applied_pass_to_report() -> None:
    summary = _summary(_LOCAL_SUMMARY)
    report = _ROOT / "docs" / summary["report"]
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == _LOCAL_SOURCE_COMMIT
        and summary["report_sha256"] == _digest(report)
        and summary["pass"]["status"] == "applied"
        and summary["ida_pro"]["status"] == summary["ghidra"]["status"] == "completed"
        and summary["readiness"]["all_named_adversarial_analyzers"] == "open"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
    )
