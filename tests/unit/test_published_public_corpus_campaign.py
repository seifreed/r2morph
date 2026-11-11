"""Regression checks for the pinned public corpus differential campaign."""

from __future__ import annotations

import json
import re
from pathlib import Path

from scripts.independent_review import _review_public_corpus_differential
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-public-corpus-2026-11-11-43064188826.json"
_SAMPLE_COUNT = 360
_DIFFERENTIAL_COUNT = 2160
_SHARD_COUNT = 4
_WORKFLOW_RUN = 43064188826
_DIFFERENTIAL_RECORDS_PER_SHARD = _DIFFERENTIAL_COUNT // _SHARD_COUNT
_EXPECTED_PASSES = {
    "BlockReordering",
    "CodeVirtualization",
    "InstructionExpansion",
    "InstructionSubstitution",
    "NopInsertion",
    "RegisterSubstitution",
}
_HOST_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", "/home/")


def test_public_corpus_campaign_covers_unique_samples_and_all_selected_passes() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["workflow_run"] == _WORKFLOW_RUN
        and report["source_commit"] == "52dfc2eac82584149dcb6e4c83dd08fd03c040a6"
        and report["completed_corpus_shards"] == report["expected_corpus_shards"] == _SHARD_COUNT
        and report["selected_samples"] == report["unique_sample_ids"] == _SAMPLE_COUNT
        and set(report["passes"]) == _EXPECTED_PASSES
    )


def test_public_corpus_campaign_records_clean_differential_outcomes() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["differential_records"] == report["differential_passed"] == _DIFFERENTIAL_COUNT
        and report["differential_failed"] == report["pass_errors"] == 0
        and all(
            result["samples"] == result["differential_passed"] == _SAMPLE_COUNT
            and result["differential_failed"] == result["errors"] == 0
            for result in report["passes"].values()
        )
    )


def test_public_corpus_campaign_covers_declared_compiler_and_build_dimensions() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    dimensions = report["sample_dimensions"]

    expect(
        dimensions["compiler"] == {"clang": 175, "clang++": 5, "g++": 5, "gcc": 175}
        and dimensions["language"] == {"c": 350, "c++": 10}
        and dimensions["optimization"] == {"O0": 72, "O1": 72, "O2": 72, "O3": 72, "Os": 72}
        and dimensions["link"] == {"dynamic": 288, "static": 72}
        and dimensions["pie"] == {"non-pie": 288, "pie": 72}
        and dimensions["symbols"] == {"stripped": 72, "symbols": 288}
    )


def test_public_corpus_campaign_pins_four_successful_radare2_measurement_shards() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    shards = report["shards"]
    digest_fields = ("selected_manifest_sha256", "matrix_report_sha256", "tools_report_sha256")

    expect(
        len(shards) == _SHARD_COUNT
        and {shard["index"] for shard in shards} == set(range(_SHARD_COUNT))
        and all(shard["sample_count"] == _SAMPLE_COUNT // _SHARD_COUNT for shard in shards)
        and all(
            shard["differential_passed"] == _DIFFERENTIAL_RECORDS_PER_SHARD and shard["differential_failed"] == 0
            for shard in shards
        )
        and report["radare2_measurements"] == _DIFFERENTIAL_COUNT
        and report["radare2_measurement_failures"] == 0
        and all(re.fullmatch(r"[0-9a-f]{64}", shard[field]) for shard in shards for field in digest_fields)
    )


def test_public_corpus_campaign_does_not_expose_analyst_paths() -> None:
    report = _REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report for marker in _HOST_PATH_MARKERS))


def test_public_corpus_review_accepts_successful_aggregate_job() -> None:
    result = _review_public_corpus_differential(_ROOT)

    expect(result["status"] == "passed")


def test_public_corpus_review_rejects_failed_aggregate_job(tmp_path: Path) -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    report["aggregate_job"]["status"] = "failure"
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / _REPORT.name).write_text(json.dumps(report), encoding="utf-8")

    result = _review_public_corpus_differential(tmp_path)

    expect(result["status"] == "failed")


def test_public_corpus_review_rejects_malformed_shard_digest(tmp_path: Path) -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    report["shards"][0]["matrix_report_sha256"] = "invalid"
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / _REPORT.name).write_text(json.dumps(report), encoding="utf-8")

    result = _review_public_corpus_differential(tmp_path)

    expect(result["status"] == "failed")
