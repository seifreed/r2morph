"""Verify the current-source local analyzer shard and its limitations."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs" / "protection-adversarial-local-allpasses-shard-2026-11-16-ae2bf209-summary.json"
_REPORT = _ROOT / "docs" / "protection-adversarial-local-allpasses-shard-2026-11-16-ae2bf209.json.gz"
_FIXTURE_NAMES = (
    "elf_vm_arith_x86_64",
    "elf_vm_call_x86_64",
    "elf_vm_multiexit_x86_64",
    "elf_vm_varargs_x86_64",
)
_PASS_COUNT = 22
_PASS_ROWS = 88
_APPLIED_PASS_ROWS = 8
_NO_OP_PASS_ROWS = 80
_EXPECTED_TOOL_RUNS = 792
_COMPLETED_TOOL_RUNS = 704
_UNAVAILABLE_TOOL_RUNS = 88
_HOST_PATH = re.compile(rb"(?:/(?:Users|home|tmp|root|workspace|private/tmp)/|[A-Za-z]:\\Users\\)")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def test_local_ida_shard_binds_report_source_and_fixture_hashes() -> None:
    summary = _summary()
    report = summary["report"]
    fixtures = summary["scope"]["fixtures"]

    expect(
        summary["source_commit"] == "ae2bf20962623ab2d905a2165d8fb217e56c1985"
        and report["sha256"] == hashlib.sha256(_REPORT.read_bytes()).hexdigest()
        and report["uncompressed_sha256"] == hashlib.sha256(gzip.decompress(_REPORT.read_bytes())).hexdigest()
        and tuple(row["name"] for row in fixtures) == _FIXTURE_NAMES
        and all(
            row["sha256"] == hashlib.sha256((_ROOT / "fixtures" / "dataset" / row["name"]).read_bytes()).hexdigest()
            for row in fixtures
        )
    )


def test_local_ida_shard_records_complete_ida_and_open_analyzer_gate() -> None:
    summary = _summary()
    analyzers = summary["tool_coverage"]["analyzers"]

    expect(
        summary["scope"]["pass_count"] == _PASS_COUNT
        and summary["scope"]["expected_pass_runs"] == summary["scope"]["observed_pass_runs"] == _PASS_ROWS
        and summary["pass_status_counts"] == {"applied": _APPLIED_PASS_ROWS, "errors": 0, "no-op": _NO_OP_PASS_ROWS}
        and summary["tool_coverage"]["expected_runs"] == _EXPECTED_TOOL_RUNS
        and summary["tool_coverage"]["completed_runs"] == _COMPLETED_TOOL_RUNS
        and summary["tool_coverage"]["unavailable_runs"] == _UNAVAILABLE_TOOL_RUNS
        and summary["tool_coverage"]["error_runs"] == 0
        and analyzers["ida-pro"]["completed"] == _PASS_ROWS
        and analyzers["binary-ninja"]["unavailable_reasons"]
        == {"analyzer license is unavailable": _UNAVAILABLE_TOOL_RUNS}
        and summary["release_criteria"]["all_named_adversarial_analyzers"] == "open"
        and summary["release_criteria"]["published_resistance_results"] == "open"
    )


def test_local_ida_shard_report_does_not_disclose_host_paths() -> None:
    report = gzip.decompress(_REPORT.read_bytes())

    expect(_HOST_PATH.search(report) is None)
