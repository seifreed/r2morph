"""Verify the current-source adversarial evidence archive and its limits."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-2026-11-18-44142495055-summary.json"
_ARCHIVE_PATH = _ROOT / "docs/protection-adversarial-2026-11-18-44142495055.tar.gz"
_REVIEW_PATH = _ROOT / "docs/protection-independent-review-run-2026-11-18-44166019050.json"
_REVIEW_REPORT_PATH = _ROOT / "docs/independent-review.json"
_WORKFLOW_REVIEW_REPORT_PATH = _ROOT / "docs/independent-review-workflow-44166019050.json"
_SOURCE_COMMIT = "b656b0dcd34af43e13db7e9b117ea401c2fbe6fd"
_BENCHMARK_RUN_ID = 44142495055
_REVIEW_RUN_ID = 44166019050
_SHARD_COUNT = 32
_SAMPLE_COUNT = 362
_PASS_COUNT = 22
_PASS_ROW_COUNT = 7964
_EXPECTED_TOOL_ROWS = 71676
_COMPLETED_TOOL_ROWS = 55220
_UNAVAILABLE_TOOL_ROWS = 16456
_UNICORN_UNAVAILABLE_ROWS = 528
_RESISTANCE_FIXTURE_COUNT = 15
_SEED_COUNT = 10
_PROGRESSIVE_GROWTH_FIXTURES = 6
_SIMILARITY_ABOVE_THRESHOLD_COUNT = 388
_REVIEW_CHECK_COUNT = 28
_CANONICAL_REVIEW_CHECK_COUNT = 27
_ZERO = 0
_HOST_PATH = re.compile(rb"(?:/(?:Users|Applications|private|tmp|home|root|workspace)/|[A-Za-z]:\\Users\\)")


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY_PATH.read_text(encoding="utf-8")))


def _archive_files() -> dict[str, bytes]:
    with tarfile.open(_ARCHIVE_PATH, mode="r:gz") as archive:
        return {
            member.name: extracted.read()
            for member in archive.getmembers()
            if member.isfile() and (extracted := archive.extractfile(member)) is not None
        }


def test_adversarial_archive_matches_source_run_and_hash() -> None:
    summary = _summary()
    archive = summary["archive"]
    workflow = summary["workflow"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and workflow["run_id"] == _BENCHMARK_RUN_ID
        and workflow["status"] == "success"
        and workflow["shard_jobs"] == _SHARD_COUNT
        and workflow["aggregate_job_status"] == "success"
        and archive["path"] == str(_ARCHIVE_PATH.relative_to(_ROOT))
        and archive["bytes"] == _ARCHIVE_PATH.stat().st_size
        and archive["sha256"] == hashlib.sha256(_ARCHIVE_PATH.read_bytes()).hexdigest()
    )


def test_adversarial_archive_contains_all_hash_bound_reports() -> None:
    summary = _summary()
    files = _archive_files()
    manifest = summary["archive"]["files"]

    expect(
        len(files) == len(manifest)
        and set(files) == {item["path"] for item in manifest}
        and all(
            len(files[item["path"]]) == item["bytes"]
            and hashlib.sha256(files[item["path"]]).hexdigest() == item["sha256"]
            for item in manifest
        )
    )


def test_adversarial_archive_covers_all_shards_without_host_paths() -> None:
    files = _archive_files()
    shard_paths = {f"adversarial/shards/{shard:02d}.json" for shard in range(_SHARD_COUNT)}

    expect(shard_paths <= files.keys() and all(_HOST_PATH.search(content) is None for content in files.values()))


def test_adversarial_campaign_records_incomplete_analyzers_and_resistance_limits() -> None:
    summary = _summary()
    scope = summary["scope"]
    analyzers = summary["analyzers"]
    resistance = summary["vm_resistance_smoke"]

    expect(
        scope["samples"] == _SAMPLE_COUNT
        and scope["passes"] == _PASS_COUNT
        and scope["pass_rows"] == _PASS_ROW_COUNT
        and scope["expected_tool_rows"] == _EXPECTED_TOOL_ROWS
        and scope["completed_tool_rows"] == _COMPLETED_TOOL_ROWS
        and scope["unavailable_tool_rows"] == _UNAVAILABLE_TOOL_ROWS
        and scope["error_tool_rows"] == _ZERO
        and scope["missing_tool_rows"] == _ZERO
        and analyzers["unavailable"]["binary-ninja"]["unavailable_runs"] == _PASS_ROW_COUNT
        and analyzers["unavailable"]["ida-pro"]["unavailable_runs"] == _PASS_ROW_COUNT
        and analyzers["partial"]["unicorn"]["unavailable_runs"] == _UNICORN_UNAVAILABLE_ROWS
        and resistance["fixture_count"] == _RESISTANCE_FIXTURE_COUNT
        and resistance["seed_count_per_fixture"] == _SEED_COUNT
        and resistance["semantic_parity"] is True
        and resistance["progressive_growth_supported_fixtures"] == _PROGRESSIVE_GROWTH_FIXTURES
        and resistance["cross_seed_similarity_above_0_8_count"] == _SIMILARITY_ABOVE_THRESHOLD_COUNT
        and resistance["human_review_status"] == "pending-human-adversarial-review"
    )


def test_independent_review_keeps_current_human_signoff_and_release_gates_open() -> None:
    manifest = json.loads(_REVIEW_PATH.read_text(encoding="utf-8"))
    report_bytes = _REVIEW_REPORT_PATH.read_bytes()
    report = json.loads(report_bytes)
    workflow_report_bytes = _WORKFLOW_REVIEW_REPORT_PATH.read_bytes()
    workflow_report = json.loads(workflow_report_bytes)
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        manifest["workflow_run"] == _REVIEW_RUN_ID
        and manifest["source_commit"] == _SOURCE_COMMIT
        and manifest["checks"]["passed"] == _REVIEW_CHECK_COUNT
        and manifest["checks"]["failed"] == _ZERO
        and manifest["checks"]["total"] == _REVIEW_CHECK_COUNT
        and manifest["checks"]["canonical_passed"] == _CANONICAL_REVIEW_CHECK_COUNT
        and manifest["report_sha256"] == hashlib.sha256(report_bytes).hexdigest()
        and manifest["workflow_report_sha256"] == hashlib.sha256(workflow_report_bytes).hexdigest()
        and len(report["checks"]) == _CANONICAL_REVIEW_CHECK_COUNT
        and report["passed"] is True
        and len(workflow_report["checks"]) == _REVIEW_CHECK_COUNT
        and workflow_report["passed"] is True
        and manifest["human_review"]["reviewed_commit"] != _SOURCE_COMMIT
        and manifest["current_human_signoff"] == "not-attested"
        and report["release_decision"]["status"] == "block-vm-milestone"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_readme_and_blocker_ledger_describe_the_published_campaign() -> None:
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    blockers = (_ROOT / "docs/release-blockers.md").read_text(encoding="utf-8")

    expect(
        "44142495055" in readme
        and "55,220" in readme
        and "does not establish generalized resistance" in readme
        and "44142495055" in blockers
        and "all-named-analyzers gate remains open" in blockers
        and "a111f923df43a66826b71ab70db8a484532fbf3b" in blockers
    )
