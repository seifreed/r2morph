"""Verify the archived Linux adversarial campaign and its VM resistance smoke."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = "docs/protection-adversarial-run-2026-11-16-43800549091.json"
_ARCHIVE_PATH = "docs/protection-adversarial-run-2026-11-16-43800549091.json.gz"
_VM_PATH = "docs/protection-adversarial-vm-resistance-2026-11-16-43800549091.json"
_SEED_PATH = "docs/protection-adversarial-seed-diversity-2026-11-16-43800549091.json"
_GRAMMAR_PATH = "docs/protection-adversarial-bytecode-grammar-2026-11-16-43800549091.json"
_XML_PATH = "docs/protection-adversarial-vm-resistance-2026-11-16-43800549091.xml"
_SOURCE_COMMIT = "e86a782959b50282cb41c8d851eba4c1e8de0965"
_WORKFLOW_RUN = 43_800_549_091
_SAMPLE_COUNT = 362
_PASS_COUNT = 22
_PASS_RUNS = 7_964
_ANALYZER_RUNS = 71_676
_COMPLETED_ANALYZER_RUNS = 55_220
_UNAVAILABLE_ANALYZER_RUNS = 16_456
_UNAVAILABLE_TOOL_RUNS = 7_964
_UNICORN_UNAVAILABLE_RUNS = 528
_EVIDENCE_BLOCKERS = 17
_VM_FIXTURES = 15
_VM_SEEDS = 10
_GROWTH_FIXTURES = 6
_COMPLETION_PERCENT = 77.04
_VM_SMOKE_CASES = 10
_ZERO = 0
_CHUNK_BYTES = 1024 * 1024
_PATH_CONTEXT_BYTES = 256
_HOST_PATH = re.compile(rb"(?:/(?:Users|home|tmp|root|workspace|private/tmp)/|[A-Za-z]:\\Users\\)")


def _json(path: str) -> dict[str, object]:
    return json.loads((_ROOT / path).read_text(encoding="utf-8"))


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _uncompressed_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = _ZERO
    with gzip.open(path, "rb") as source:
        for chunk in iter(lambda: source.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _contains_host_path(path: Path) -> bool:
    trailing = b""
    with gzip.open(path, "rb") as source:
        for chunk in iter(lambda: source.read(_CHUNK_BYTES), b""):
            content = trailing + chunk
            if _HOST_PATH.search(content):
                return True
            trailing = content[-_PATH_CONTEXT_BYTES:]
    return False


def test_adversarial_campaign_archive_matches_published_hashes() -> None:
    summary = _json(_SUMMARY_PATH)
    archive = summary["archive"]
    archive_path = _ROOT / _ARCHIVE_PATH
    uncompressed_sha256, uncompressed_size = _uncompressed_digest(archive_path)

    expect(
        archive["path"] == _ARCHIVE_PATH
        and archive["sha256"] == _digest(archive_path)
        and archive["uncompressed_sha256"] == uncompressed_sha256
        and archive["uncompressed_bytes"] == uncompressed_size
    )


def test_adversarial_campaign_binds_complete_workflow_and_corpus() -> None:
    summary = _json(_SUMMARY_PATH)

    expect(
        summary["workflow"]["run_id"] == _WORKFLOW_RUN
        and summary["workflow"]["source_commit"] == _SOURCE_COMMIT
        and summary["workflow"]["conclusion"] == "success"
        and summary["workflow"]["jobs"] == {"failed": _ZERO, "skipped": _ZERO, "successful": 33, "total": 33}
        and summary["scope"]["sample_count"] == _SAMPLE_COUNT
        and summary["scope"]["pass_count"] == _PASS_COUNT
        and summary["scope"]["expected_pass_runs"] == _PASS_RUNS
        and summary["scope"]["observed_pass_runs"] == _PASS_RUNS
    )


def test_adversarial_campaign_accounts_for_all_pass_runs_without_errors() -> None:
    summary = _json(_SUMMARY_PATH)
    results = summary["results"]

    expect(
        results["expected_analyzer_runs"] == _ANALYZER_RUNS
        and results["observed_analyzer_runs"] == _ANALYZER_RUNS
        and results["completed_analyzer_runs"] == _COMPLETED_ANALYZER_RUNS
        and results["unavailable_analyzer_runs"] == _UNAVAILABLE_ANALYZER_RUNS
        and results["analyzer_errors"] == results["pass_errors"] == _ZERO
        and results["missing_pass_runs"] == _ZERO
        and results["applied_pass_runs"] > _ZERO
    )


def test_adversarial_campaign_keeps_unavailable_analyzers_and_blockers_visible() -> None:
    results = _json(_SUMMARY_PATH)["results"]

    expect(
        results["completed_analyzer_percent"] == _COMPLETION_PERCENT
        and results["unavailable_runs_by_tool"]["binary-ninja"] == _UNAVAILABLE_TOOL_RUNS
        and results["unavailable_runs_by_tool"]["ida-pro"] == _UNAVAILABLE_TOOL_RUNS
        and results["unavailable_runs_by_tool"]["unicorn"] == _UNICORN_UNAVAILABLE_RUNS
        and results["evidence_blocker_totals"]["total_adversarial_evidence_blockers"] == _EVIDENCE_BLOCKERS
    )


def test_vm_resistance_smoke_reports_limited_automated_evidence() -> None:
    summary = _json(_SUMMARY_PATH)
    vm = summary["vm_resistance_smoke"]

    expect(
        vm["fixture_count"] == _VM_FIXTURES
        and vm["seed_count"] == _VM_SEEDS
        and vm["semantic_parity"] is True
        and vm["progressive_growth_supported_fixture_count"] == _GROWTH_FIXTURES
        and vm["general_resistance_established"] is False
        and vm["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
    )


def test_vm_resistance_smoke_junit_contains_ten_unskipped_cases() -> None:
    suite = ElementTree.parse(_ROOT / _XML_PATH).getroot()

    expect(
        len(suite.findall(".//testcase")) == _VM_SMOKE_CASES
        and not suite.findall(".//failure")
        and not suite.findall(".//error")
        and not suite.findall(".//skipped")
    )


def test_vm_resistance_reports_match_published_digests() -> None:
    summary = _json(_SUMMARY_PATH)
    reports = summary["vm_resistance_smoke"]["reports"]

    expect(all(report["sha256"] == _digest(_ROOT / report["path"]) for report in reports.values()))


def test_adversarial_campaign_retains_open_readiness_gates() -> None:
    readiness = _json("docs/one-zero-readiness.json")

    expect(
        readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _SUMMARY_PATH in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
        and _ARCHIVE_PATH in readiness["criteria"]["published_resistance_results"]["evidence"]
        and _VM_PATH in readiness["criteria"]["published_resistance_results"]["evidence"]
    )


def test_adversarial_archive_does_not_disclose_host_paths() -> None:
    expect(not _contains_host_path(_ROOT / _ARCHIVE_PATH))
