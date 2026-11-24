"""Checks the hash-bound 2026-11-24 adversarial analyzer and VM reports."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-run-2026-11-24-45488041450-summary.json"
_ANALYZER_REPORT = _ROOT / "docs/protection-adversarial-run-2026-11-24-45488041450.json.gz"
_RESISTANCE_REPORT = _ROOT / "docs/protection-vm-resistance-run-2026-11-24-45488041450.json.gz"
_SEED_REPORT = _ROOT / "docs/protection-vm-seed-diversity-2026-11-24-45488041450.json"
_GRAMMAR_REPORT = _ROOT / "docs/protection-vm-bytecode-grammar-2026-11-24-45488041450.json"
_SOURCE_COMMIT = "4d456ac818845e6fdd92ccce9411dc60612d7105"
_WORKFLOW_RUN = 45_488_041_450
_EXPECTED_PASS_RUNS = 7_964
_EXPECTED_TOOL_RUNS = 71_676
_COMPLETED_TOOL_RUNS = 55_220
_UNAVAILABLE_TOOL_RUNS = 16_456
_JOB_COUNT = 33
_SAMPLE_COUNT = 362
_GENERATED_FIXTURE_COUNT = 200
_PASS_COUNT = 22
_UNICORN_UNAVAILABLE_RUNS = 528
_RESISTANCE_FIXTURE_COUNT = 15
_SEED_COUNT = 10
_GROWTH_FIXTURE_COUNT = 6
_CROSS_SEED_SIMILARITY_COMPARISONS = 2_295
_CROSS_SEED_SIMILARITY_OVER_THRESHOLD = 328
_CROSS_SEED_SIMILARITY_MAX = 0.9333333333333333
_ZERO = 0
_CHUNK_BYTES = 1024 * 1024
_PATH_CONTEXT_BYTES = 256
_HOST_PATH = re.compile(rb"(?:/(?:Users|home|tmp|root|workspace|private/tmp)/|[A-Za-z]:\\Users\\)")


def _json(path: Path) -> dict[str, object]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as report:
        return json.loads(report.read())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _uncompressed_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = _ZERO
    with gzip.open(path, "rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _contains_host_path(path: Path) -> bool:
    trailing_bytes = b""
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as report:
        for chunk in iter(lambda: report.read(_CHUNK_BYTES), b""):
            content = trailing_bytes + chunk
            if _HOST_PATH.search(content):
                return True
            trailing_bytes = content[-_PATH_CONTEXT_BYTES:]
    return False


def test_adversarial_run_archives_match_published_hashes() -> None:
    summary = _json(_SUMMARY)

    expect(
        all(
            archive["sha256"] == _sha256(_ROOT / "docs" / path)
            and archive["uncompressed_sha256"] == _uncompressed_digest(_ROOT / "docs" / path)[0]
            and archive["uncompressed_size_bytes"] == _uncompressed_digest(_ROOT / "docs" / path)[1]
            for path, archive in summary["archives"].items()
            if path.endswith(".gz")
        )
        and all(not _contains_host_path(_ROOT / "docs" / path) for path in summary["archives"])
    )


def test_adversarial_run_records_all_shards_and_analyzer_gaps() -> None:
    summary = _json(_SUMMARY)
    results = summary["results"]
    readiness = _json(_ROOT / "docs/one-zero-readiness.json")

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["workflow"]["run_id"] == _WORKFLOW_RUN
        and summary["workflow"]["jobs"]
        == {"total": _JOB_COUNT, "successful": _JOB_COUNT, "failed": _ZERO, "skipped": _ZERO}
        and summary["scope"]["sample_count"] == _SAMPLE_COUNT
        and summary["scope"]["generated_fixture_count"] == _GENERATED_FIXTURE_COUNT
        and summary["scope"]["pass_count"] == _PASS_COUNT
        and summary["scope"]["expected_pass_runs"] == _EXPECTED_PASS_RUNS
        and summary["scope"]["expected_tool_runs"] == _EXPECTED_TOOL_RUNS
        and results["completed_tool_runs"] == _COMPLETED_TOOL_RUNS
        and results["unavailable_tool_runs"] == _UNAVAILABLE_TOOL_RUNS
        and results["error_tool_runs"] == _ZERO
        and results["missing_tool_runs"] == _ZERO
        and results["unavailable_tool_runs_by_tool"]["binary-ninja"] == _EXPECTED_PASS_RUNS
        and results["unavailable_tool_runs_by_tool"]["ida-pro"] == _EXPECTED_PASS_RUNS
        and results["unavailable_tool_runs_by_tool"]["unicorn"] == _UNICORN_UNAVAILABLE_RUNS
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
    )


def test_vm_resistance_evidence_preserves_automated_scope_and_open_gate() -> None:
    summary = _json(_SUMMARY)
    measurement = summary["vm_resistance"]
    readiness = _json(_ROOT / "docs/one-zero-readiness.json")

    expect(
        measurement["fixture_count"] == _RESISTANCE_FIXTURE_COUNT
        and measurement["seed_count"] == _SEED_COUNT
        and measurement["semantic_parity"] is True
        and measurement["all_tamper_probes_diverged"] is True
        and measurement["progressive_growth_supported_fixture_count"] == _GROWTH_FIXTURE_COUNT
        and measurement["cross_seed_exact_normalised_matches"] == _ZERO
        and measurement["cross_seed_nearest_similarity_above_threshold"] == _CROSS_SEED_SIMILARITY_OVER_THRESHOLD
        and measurement["cross_seed_nearest_similarity_comparisons"] == _CROSS_SEED_SIMILARITY_COMPARISONS
        and measurement["cross_seed_nearest_similarity_max"] == _CROSS_SEED_SIMILARITY_MAX
        and measurement["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        and summary["readiness"]["published_resistance_results"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _json(_SEED_REPORT)["cross_seed_exact_normalised_matches"] == _ZERO
        and _json(_GRAMMAR_REPORT)["seed_count"] == _SEED_COUNT
    )


def test_campaign_dependency_difference_is_explicit() -> None:
    summary = _json(_SUMMARY)

    expect(
        any("current dependency commit requires angr>=10.0.7" in limit for limit in summary["limits"])
        and any("does not validate the current dependency stack" in limit for limit in summary["limits"])
    )
