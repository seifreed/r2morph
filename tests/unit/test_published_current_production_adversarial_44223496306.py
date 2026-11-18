"""Verify the complete current-production analyzer campaign and bounded claims."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from collections import Counter
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-current-production-adversarial-2026-11-18-44223496306-summary.json"
_ARCHIVE_PATH = _ROOT / "docs/protection-current-production-adversarial-2026-11-18-44223496306.tar.gz"
_SOURCE_COMMIT = "1cf52005310a527b86c68b4ff713ce248f1432d7"
_VERIFIED_THROUGH_COMMIT = "42a07930b4140d3598a8dd509e67cc229dadb86a"
_RUN_ID = 44223496306
_SHARD_COUNT = 32
_ARCHIVE_MEMBER_COUNT = 37
_PASS_RUN_COUNT = 7964
_ANALYZER_RUN_COUNT = 71676
_COMPLETED_ANALYZER_RUN_COUNT = 55220
_UNAVAILABLE_ANALYZER_RUN_COUNT = 16456
_UNICORN_UNAVAILABLE_RUN_COUNT = 528
_VM_FIXTURE_COUNT = 15
_VM_SEED_COUNT = 10
_HOST_PATH = re.compile(rb"(?:/(?:Users|Applications|private|tmp|home|root|runner|workspace)/|[A-Za-z]:\\Users\\)")


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY_PATH.read_text(encoding="utf-8")))


def _load_member(archive: tarfile.TarFile, name: str) -> dict[str, Any]:
    member = archive.extractfile(name)
    if member is None:
        raise AssertionError(f"campaign archive lacks {name}")
    return cast(dict[str, Any], json.load(member))


def test_current_production_campaign_archive_matches_its_manifest() -> None:
    summary = _summary()
    archive = _ARCHIVE_PATH.read_bytes()

    expect(
        summary["workflow_run"] == _RUN_ID
        and summary["source_commit"] == _SOURCE_COMMIT
        and summary["production_source_verified_unchanged_through"] == _VERIFIED_THROUGH_COMMIT
        and summary["workflow_conclusion"] == "success"
        and summary["archive"]["path"] == _ARCHIVE_PATH.relative_to(_ROOT).as_posix()
        and summary["archive"]["sha256"] == hashlib.sha256(archive).hexdigest()
        and summary["archive"]["members"] == _ARCHIVE_MEMBER_COUNT
    )


def test_current_production_campaign_accounts_for_all_shards_and_rows() -> None:
    summary = _summary()
    shard_names = [f"adversarial-benchmark/shard-{index:02d}.json" for index in range(_SHARD_COUNT)]
    fixture_names: set[str] = set()
    completed_runs: Counter[str] = Counter()
    unavailable_runs: Counter[str] = Counter()
    sample_count = pass_runs = analyzer_runs = 0
    valid_shards = True

    with tarfile.open(_ARCHIVE_PATH, mode="r:gz") as archive:
        for index, name in enumerate(shard_names):
            report = _load_member(archive, name)
            shard = report["fixture_shard"]
            result = report["summary"]
            sample_count += report["sample_count"]
            pass_runs += result["observed_pass_runs"]
            analyzer_runs += result["observed_tool_runs"]
            fixture_names.update(sample["original"] for sample in report["samples"])
            for tool, counts in report["tool_summary"].items():
                completed_runs[tool] += counts["completed"]
                unavailable_runs[tool] += counts["unavailable"]
            valid_shards = valid_shards and (
                shard["index"] == index
                and shard["count"] == _SHARD_COUNT
                and result["error_pass_runs"] == result["missing_pass_runs"] == 0
                and result["error_tool_runs"] == result["missing_tool_runs"] == 0
            )

    expect(
        valid_shards
        and sample_count == len(fixture_names) == summary["corpus"]["fixture_count"]
        and pass_runs == summary["corpus"]["observed_pass_runs"] == _PASS_RUN_COUNT
        and analyzer_runs == summary["corpus"]["observed_analyzer_runs"] == _ANALYZER_RUN_COUNT
        and completed_runs == Counter(summary["results"]["completed_runs_by_tool"])
        and unavailable_runs == Counter(summary["results"]["unavailable_runs_by_tool"])
    )
    archive.close()


def test_current_production_campaign_records_unavailable_analyzer_limits() -> None:
    results = _summary()["results"]

    expect(
        results["completed_analyzer_runs"] == _COMPLETED_ANALYZER_RUN_COUNT
        and results["unavailable_analyzer_runs"] == _UNAVAILABLE_ANALYZER_RUN_COUNT
        and results["analyzer_errors"] == results["missing_analyzer_runs"] == 0
        and results["completed_runs_by_tool"]["triton"] == _PASS_RUN_COUNT
        and results["completed_runs_by_tool"]["ghidra"] == _PASS_RUN_COUNT
        and results["unavailable_runs_by_tool"]["binary-ninja"] == _PASS_RUN_COUNT
        and results["unavailable_runs_by_tool"]["ida-pro"] == _PASS_RUN_COUNT
        and results["unavailable_runs_by_tool"]["unicorn"] == _UNICORN_UNAVAILABLE_RUN_COUNT
    )


def test_current_production_campaign_keeps_human_vm_review_pending() -> None:
    with tarfile.open(_ARCHIVE_PATH, mode="r:gz") as archive:
        vm_report = _load_member(archive, "vm-resistance/adversarial.json")

        expect(
            vm_report["fixture_count"] == _VM_FIXTURE_COUNT
            and vm_report["seed_count"] == _VM_SEED_COUNT
            and vm_report["automated_validation"]["status"] == "completed"
            and vm_report["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
        )


def test_current_production_campaign_archive_contains_no_host_paths() -> None:
    with tarfile.open(_ARCHIVE_PATH, mode="r:gz") as archive:
        expect(
            all(
                member_file is not None and _HOST_PATH.search(member_file.read()) is None
                for member in archive.getmembers()
                if (member_file := archive.extractfile(member)) is not None
            )
        )


def test_current_production_campaign_keeps_release_gates_open() -> None:
    summary = _summary()
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence_paths = {
        _SUMMARY_PATH.relative_to(_ROOT).as_posix(),
        _ARCHIVE_PATH.relative_to(_ROOT).as_posix(),
        "tests/unit/test_published_current_production_adversarial_44223496306.py",
    }

    expect(
        all(status == "open" for status in summary["release_criteria"].values())
        and all(
            readiness["criteria"][criterion]["status"] == "open"
            and evidence_paths <= set(readiness["criteria"][criterion]["evidence"])
            for criterion in ("all_named_adversarial_analyzers", "published_resistance_results")
        )
    )
