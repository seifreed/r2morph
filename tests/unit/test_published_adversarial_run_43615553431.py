"""Checks hash-bound evidence from the complete Linux adversarial run."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_ADVERSARIAL_SUMMARY = _ROOT / "docs/protection-adversarial-run-2026-11-14-43615553431.json"
_RESISTANCE_SUMMARY = _ROOT / "docs/protection-vm-resistance-run-2026-11-14-43615553431.json"
_SOURCE_COMMIT = "fadc0e6302ba722f5e397cdafe70f33506baea99"
_SCOPE_COMMIT = "16eedca70d31564f45a7d8911ceb549882f3df09"
_WORKFLOW_RUN = 43_615_553_431
_SAMPLE_COUNT = 362
_PASS_COUNT = 22
_EXPECTED_PASS_RUNS = 7_964
_EXPECTED_TOOL_RUNS = 71_676
_COMPLETED_TOOL_RUNS = 55_220
_UNAVAILABLE_TOOL_RUNS = 16_456
_UNICORN_UNAVAILABLE_RUNS = 528
_ADVERSARIAL_BLOCKER_COUNT = 17
_RESISTANCE_FIXTURE_COUNT = 15
_RESISTANCE_SEED_COUNT = 10
_GROWTH_FIXTURE_COUNT = 6
_ZERO = 0
_CHUNK_BYTES = 1024 * 1024
_PATH_CONTEXT_BYTES = 256
_HOST_PATH = re.compile(rb"(?:/(?:Users|home|tmp|root|workspace|private/tmp)/|[A-Za-z]:\\Users\\)")


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


def _contains_host_path(path: Path) -> bool:
    trailing_bytes = b""
    with gzip.open(path, "rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            content = trailing_bytes + chunk
            if _HOST_PATH.search(content):
                return True
            trailing_bytes = content[-_PATH_CONTEXT_BYTES:]
    return False


def test_adversarial_run_archives_match_published_hashes() -> None:
    summary = _summary(_ADVERSARIAL_SUMMARY)

    expect(
        all(
            artifact["sha256"] == _digest(_ROOT / "docs" / artifact["path"])
            and artifact["uncompressed_sha256"] == _uncompressed_digest(_ROOT / "docs" / artifact["path"])[0]
            and artifact["uncompressed_size_bytes"] == _uncompressed_digest(_ROOT / "docs" / artifact["path"])[1]
            for artifact in summary["archives"].values()
        )
    )


def test_adversarial_run_records_complete_jobs_and_analyzer_gaps() -> None:
    summary = _summary(_ADVERSARIAL_SUMMARY)
    results = summary["results"]
    readiness = _summary(_ROOT / "docs/one-zero-readiness.json")

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_scope_commit"] == _SCOPE_COMMIT
        and summary["workflow"]["run_id"] == _WORKFLOW_RUN
        and summary["workflow"]["jobs"] == {"failed": 0, "skipped": 0, "successful": 33, "total": 33}
        and summary["scope"]["samples"] == _SAMPLE_COUNT
        and summary["scope"]["passes"] == _PASS_COUNT
        and summary["scope"]["expected_pass_runs"] == _EXPECTED_PASS_RUNS
        and summary["scope"]["expected_tool_runs"] == _EXPECTED_TOOL_RUNS
        and results["completed_tool_runs"] == _COMPLETED_TOOL_RUNS
        and results["unavailable_tool_runs"] == _UNAVAILABLE_TOOL_RUNS
        and results["error_tool_runs"] == _ZERO
        and results["missing_tool_runs"] == _ZERO
        and results["unavailable_tool_runs_by_tool"]["binary-ninja"] == _EXPECTED_PASS_RUNS
        and results["unavailable_tool_runs_by_tool"]["ida-pro"] == _EXPECTED_PASS_RUNS
        and results["unavailable_tool_runs_by_tool"]["unicorn"] == _UNICORN_UNAVAILABLE_RUNS
        and results["blocker_totals"]["total_adversarial_evidence_blockers"] == _ADVERSARIAL_BLOCKER_COUNT
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
    )


def test_vm_resistance_run_archives_match_published_hashes() -> None:
    summary = _summary(_RESISTANCE_SUMMARY)

    expect(
        summary["workflow_run"] == _WORKFLOW_RUN
        and summary["source_commit"] == _SOURCE_COMMIT
        and all(
            artifact["sha256"] == _digest(_ROOT / "docs" / artifact["path"])
            and artifact["uncompressed_sha256"] == _uncompressed_digest(_ROOT / "docs" / artifact["path"])[0]
            for artifact in summary["artifacts"].values()
        )
    )


def test_vm_resistance_run_keeps_human_review_and_release_gate_open() -> None:
    summary = _summary(_RESISTANCE_SUMMARY)
    measurement = summary["measurement"]
    readiness = _summary(_ROOT / "docs/one-zero-readiness.json")

    expect(
        measurement["fixture_count"] == _RESISTANCE_FIXTURE_COUNT
        and measurement["seed_count"] == _RESISTANCE_SEED_COUNT
        and measurement["semantic_parity"] is True
        and measurement["all_tamper_probes_diverged"] is True
        and measurement["opcode_assignment_diversity_observed"] is True
        and measurement["handler_diversity_observed"] is True
        and measurement["dispatcher_diversity_observed"] is True
        and measurement["progressive_growth_supported_fixture_count"] == _GROWTH_FIXTURE_COUNT
        and summary["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        and summary["readiness"]["published_resistance_results"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_published_adversarial_archives_do_not_disclose_host_paths() -> None:
    campaign = _summary(_ADVERSARIAL_SUMMARY)
    resistance = _summary(_RESISTANCE_SUMMARY)
    archives = [
        artifact["path"]
        for artifacts in (campaign["archives"], resistance["artifacts"])
        for artifact in artifacts.values()
    ]

    expect(not any(_contains_host_path(_ROOT / "docs" / path) for path in archives))
