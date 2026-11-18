"""Verify the second current-main analyzer shard and its limits."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-adversarial-current-main-2026-11-18-7cb29ce1-shard-1-summary.json"
_ARCHIVE_PATH = _ROOT / "docs/protection-adversarial-current-main-2026-11-18-7cb29ce1-shard-1.json.gz"
_SOURCE_COMMIT = "7cb29ce109d1334577b2cf20cdb2375421a55224"
_FIXTURE_COUNT = 4
_PASS_COUNT = 22
_PASS_RUN_COUNT = 88
_APPLIED_PASS_RUN_COUNT = 8
_COMPLETED_ANALYZER_RUN_COUNT = 528
_COMPLETED_TOOLS = ("angr", "custom", "ida-pro", "objdump", "radare2", "unicorn")
_UNAVAILABLE_TOOLS = ("binary-ninja", "ghidra", "triton")
_HOST_PATH = re.compile(rb"(?:/(?:Users|Applications|private|tmp|home|root|workspace)/|[A-Za-z]:\\Users\\)")


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY_PATH.read_text(encoding="utf-8")))


def _report() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(gzip.decompress(_ARCHIVE_PATH.read_bytes())))


def test_current_main_shard_archive_matches_its_manifest() -> None:
    summary = _summary()
    archive = summary["archive"]
    archive_bytes = _ARCHIVE_PATH.read_bytes()
    raw = gzip.decompress(archive_bytes)

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and archive["path"] == str(_ARCHIVE_PATH.relative_to(_ROOT))
        and archive["sha256"] == hashlib.sha256(archive_bytes).hexdigest()
        and archive["uncompressed_sha256"] == hashlib.sha256(raw).hexdigest()
        and archive["uncompressed_bytes"] == len(raw)
    )


def test_current_main_shard_matches_fixture_digests() -> None:
    fixture_records = _summary()["scope"]["fixtures"]

    expect(
        all(
            (fixture := (_ROOT / "fixtures/dataset" / record["name"]).read_bytes())
            and len(fixture) == record["bytes"]
            and hashlib.sha256(fixture).hexdigest() == record["sha256"]
            for record in fixture_records
        )
    )


def test_current_main_shard_accounts_for_each_pass_and_analyzer_slot() -> None:
    report = _report()
    summary = report["summary"]
    tools = report["tool_summary"]

    expect(
        report["sample_count"] == _FIXTURE_COUNT
        and len(report["pass_names"]) == _PASS_COUNT
        and summary["observed_pass_runs"] == summary["expected_pass_runs"] == _PASS_RUN_COUNT
        and summary["applied_pass_runs"] == _APPLIED_PASS_RUN_COUNT
        and summary["error_pass_runs"] == summary["missing_pass_runs"] == 0
        and summary["completed_tool_runs"] == _COMPLETED_ANALYZER_RUN_COUNT
        and summary["error_tool_runs"] == summary["missing_tool_runs"] == 0
        and all(tools[name]["completed"] == _PASS_RUN_COUNT for name in _COMPLETED_TOOLS)
        and all(tools[name]["unavailable"] == _PASS_RUN_COUNT for name in _UNAVAILABLE_TOOLS)
    )


def test_current_main_shard_preserves_open_release_gates() -> None:
    summary = _summary()
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence_paths = {
        str(_SUMMARY_PATH.relative_to(_ROOT)),
        str(_ARCHIVE_PATH.relative_to(_ROOT)),
        "tests/unit/test_published_current_main_adversarial_shard_7cb29ce1.py",
    }

    expect(
        all(status == "open" for status in summary["release_criteria"].values())
        and all(
            readiness["criteria"][criterion]["status"] == "open"
            and evidence_paths <= set(readiness["criteria"][criterion]["evidence"])
            for criterion in ("all_named_adversarial_analyzers", "published_resistance_results")
        )
    )


def test_current_main_shard_contains_no_analyst_host_paths() -> None:
    expect(_HOST_PATH.search(gzip.decompress(_ARCHIVE_PATH.read_bytes())) is None)
