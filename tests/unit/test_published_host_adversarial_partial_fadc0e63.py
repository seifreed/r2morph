"""Checks the published partial Linux adversarial benchmark evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-host-partial-2026-11-14-fadc0e63-summary.json"
_BUNDLE_PATH = _ROOT / "docs/protection-adversarial-host-partial-2026-11-14-fadc0e63.json.gz"
_SOURCE_COMMIT = "fadc0e6302ba722f5e397cdafe70f33506baea99"
_SCOPE_COMMIT = "8a293bfc52f6bcdb994884331796ec7249f26a78"
_WORKFLOW_RUN_ID = 43_615_553_431
_COMPLETED_SHARDS = 20
_EXPECTED_SHARDS = 32
_SAMPLE_COUNT = 139
_PASS_COUNT = 22
_PASS_ROWS = 3_058
_EXPECTED_TOOL_RUNS = 27_522
_COMPLETED_TOOL_RUNS = 21_054
_UNAVAILABLE_TOOL_RUNS = 6_468
_SHARD_INDICES = {1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 16, 17, 21, 23, 24, 29, 31}
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def _bundle() -> dict[str, object]:
    return json.loads(gzip.decompress(_BUNDLE_PATH.read_bytes()))


def test_partial_adversarial_bundle_binds_source_artifacts_and_hashes() -> None:
    summary = _summary()
    bundle_bytes = _BUNDLE_PATH.read_bytes()
    raw_bundle = gzip.decompress(bundle_bytes)
    bundle = json.loads(raw_bundle)
    shards = bundle["shards"]

    expect(
        summary["workflow_run_id"] == _WORKFLOW_RUN_ID
        and summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_scope_commit"] == _SCOPE_COMMIT
        and bundle["workflow_run"]["source_commit"] == _SOURCE_COMMIT
        and {shard["fixture_shard"]["index"] for shard in shards} == _SHARD_INDICES
        and summary["bundle_sha256"] == hashlib.sha256(bundle_bytes).hexdigest()
        and summary["uncompressed_sha256"] == hashlib.sha256(raw_bundle).hexdigest()
        and all(
            shard["report_canonical_sha256"]
            == hashlib.sha256(
                json.dumps(shard["report"], sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            for shard in shards
        )
    )


def test_partial_adversarial_bundle_covers_unique_samples_and_all_passes() -> None:
    bundle = _bundle()
    shards = bundle["shards"]
    samples = [sample for shard in shards for sample in shard["report"]["samples"]]
    sample_names = [sample["original"] for sample in samples]

    expect(
        _summary()["completed_shards"] == _COMPLETED_SHARDS
        and _summary()["expected_shards"] == _EXPECTED_SHARDS
        and len(samples) == _SAMPLE_COUNT
        and len(set(sample_names)) == _SAMPLE_COUNT
        and sum(shard["pass_rows"] for shard in shards) == _PASS_ROWS
        and all(len(sample["passes"]) == _PASS_COUNT for sample in samples)
    )


def test_partial_adversarial_bundle_records_tool_completion_and_gaps() -> None:
    summary = _summary()
    expected = {
        "angr": (3058, 0, 3058, 0),
        "binary-ninja": (0, 0, 3058, 3058),
        "custom": (3058, 0, 3058, 0),
        "ghidra": (3058, 0, 3058, 0),
        "ida-pro": (0, 0, 3058, 3058),
        "objdump": (3058, 0, 3058, 0),
        "radare2": (3058, 0, 3058, 0),
        "triton": (3058, 0, 3058, 0),
        "unicorn": (2706, 0, 3058, 352),
    }

    expect(
        summary["expected_tool_runs"] == _EXPECTED_TOOL_RUNS
        and summary["completed_tool_runs"] == _COMPLETED_TOOL_RUNS
        and summary["unavailable_tool_runs"] == _UNAVAILABLE_TOOL_RUNS
        and summary["error_tool_runs"] == 0
        and all(
            tuple(summary["tool_coverage"][tool][field] for field in ("completed", "errors", "runs", "unavailable"))
            == counts
            for tool, counts in expected.items()
        )
    )


def test_partial_adversarial_evidence_keeps_release_criteria_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _summary()["remaining_shard_indices"] == sorted(set(range(32)) - _SHARD_INDICES)
        and any(f"incomplete {_COMPLETED_SHARDS}-of-{_EXPECTED_SHARDS}" in value for value in _summary()["limitations"])
    )


def test_partial_adversarial_reports_do_not_publish_host_paths() -> None:
    text = _SUMMARY_PATH.read_text(encoding="utf-8")
    text += gzip.decompress(_BUNDLE_PATH.read_bytes()).decode("utf-8")

    expect(not any(prefix in text for prefix in _HOST_PATH_PREFIXES))
