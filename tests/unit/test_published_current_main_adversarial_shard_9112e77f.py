"""Verify current-main analyzer evidence and its bounded claims."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-current-main-2026-11-18-9112e77f-shard-0-summary.json"
_ARCHIVE_PATH = _ROOT / "docs/protection-adversarial-current-main-2026-11-18-9112e77f-shard-0.json.gz"
_SOURCE_COMMIT = "9112e77fd749b9ee24b7879012a76dda15233ee8"
_ZERO = 0
_FIXTURE_COUNT = 4
_PASS_COUNT = 22
_PASS_RUN_COUNT = 88
_COMPLETED_ANALYZER_RUN_COUNT = 528
_COMPLETED_TOOLS = ("angr", "custom", "ida-pro", "objdump", "radare2", "unicorn")
_UNAVAILABLE_TOOLS = ("binary-ninja", "ghidra", "triton")
_HOST_PATH = re.compile(rb"(?:/(?:Users|Applications|private|tmp|home|root|workspace)/|[A-Za-z]:\\Users\\)")


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY_PATH.read_text(encoding="utf-8")))


def _report() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(gzip.decompress(_ARCHIVE_PATH.read_bytes())))


def test_current_main_adversarial_shard_archive_matches_its_manifest() -> None:
    summary = _summary()
    archive = summary["archive"]
    raw = gzip.decompress(_ARCHIVE_PATH.read_bytes())

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and archive["path"] == _ARCHIVE_PATH.relative_to(_ROOT).as_posix()
        and archive["sha256"] == hashlib.sha256(_ARCHIVE_PATH.read_bytes()).hexdigest()
        and archive["uncompressed_sha256"] == hashlib.sha256(raw).hexdigest()
        and archive["uncompressed_bytes"] == len(raw)
    )


def test_current_main_adversarial_shard_matches_fixture_digests() -> None:
    fixture_records = _summary()["scope"]["fixtures"]

    expect(
        all(
            (fixture := (_ROOT / "fixtures/dataset" / record["name"]).read_bytes())
            and len(fixture) == record["bytes"]
            and hashlib.sha256(fixture).hexdigest() == record["sha256"]
            for record in fixture_records
        )
    )


def test_current_main_adversarial_shard_records_all_passes_and_analyzer_gaps() -> None:
    report = _report()
    summary = report["summary"]
    tools = report["tool_summary"]

    expect(
        report["sample_count"] == _FIXTURE_COUNT
        and len(report["pass_names"]) == _PASS_COUNT
        and summary["observed_pass_runs"] == summary["expected_pass_runs"] == _PASS_RUN_COUNT
        and summary["error_pass_runs"] == summary["missing_pass_runs"] == _ZERO
        and summary["completed_tool_runs"] == _COMPLETED_ANALYZER_RUN_COUNT
        and summary["error_tool_runs"] == summary["missing_tool_runs"] == _ZERO
        and all(tools[name]["completed"] == _PASS_RUN_COUNT for name in _COMPLETED_TOOLS)
        and all(tools[name]["unavailable"] == _PASS_RUN_COUNT for name in _UNAVAILABLE_TOOLS)
    )


def test_current_main_adversarial_shard_keeps_release_gates_open() -> None:
    summary = _summary()
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence_paths = {
        _SUMMARY_PATH.relative_to(_ROOT).as_posix(),
        _ARCHIVE_PATH.relative_to(_ROOT).as_posix(),
        "tests/unit/test_published_current_main_adversarial_shard_9112e77f.py",
    }

    expect(
        all(status == "open" for status in summary["release_criteria"].values())
        and all(
            readiness["criteria"][criterion]["status"] == "open"
            and evidence_paths <= set(readiness["criteria"][criterion]["evidence"])
            for criterion in ("all_named_adversarial_analyzers", "published_resistance_results")
        )
    )


def test_current_main_adversarial_shard_report_contains_no_host_paths() -> None:
    expect(_HOST_PATH.search(gzip.decompress(_ARCHIVE_PATH.read_bytes())) is None)
