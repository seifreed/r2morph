"""Regression checks for the pinned format-aware fuzz campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-fuzz-format-aware-2026-11-11-95cff0fb.json"
_CURRENT_REPORT = _ROOT / "docs" / "protection-fuzz-format-aware-2026-11-12-04e2f5b4.json"
_CURRENT_RAW_REPORT = _ROOT / "docs" / "protection-fuzz-2026-11-12-04e2f5b4-output.json"
_WHEEL_REPORT = _ROOT / "docs" / "protection-fuzz-wheel-2026-11-12-8d6ceb6a.json"
_WHEEL_RAW_REPORT = _ROOT / "docs" / "protection-fuzz-wheel-2026-11-12-8d6ceb6a-output.json"
_WORKFLOW_RUN = 43_067_351_979
_WHEEL_WORKFLOW_RUN = 43_132_685_797
_CASES_PER_TARGET = 20_000
_TOTAL_TARGET_RUNS = 180_000
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")
_EXPECTED_TARGETS = {
    "assembling",
    "binary_parsers",
    "elf_header_parser",
    "pe_header_parser",
    "macho_load_commands",
    "vm_dispatcher",
    "vm_bytecode",
    "relocations",
    "binary_rewriter",
}


def test_published_fuzz_campaign_covers_each_format_target() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    cases = report["cases"]

    expect(
        report["commit"] == "95cff0fb21a80fe43cda1a817cee718a45011b15"
        and report["workflow_run"] == _WORKFLOW_RUN
        and set(report["target_runs"]) == _EXPECTED_TARGETS
        and all(report["target_runs"][target] == cases == _CASES_PER_TARGET for target in _EXPECTED_TARGETS)
        and sum(report["target_runs"].values()) == _TOTAL_TARGET_RUNS
    )


def test_published_fuzz_campaign_reports_clean_parser_outcomes() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["status"] == "passed"
        and report["failure_count"] == 0
        and report["parser_diagnostic_counts"] == {"macho_load_commands.warning": 413}
    )


def test_published_fuzz_campaign_does_not_expose_host_paths() -> None:
    report = _REPORT.read_text(encoding="utf-8")

    expect(not any(prefix in report for prefix in _HOST_PATH_PREFIXES))


def test_current_local_fuzz_campaign_binds_summary_to_raw_report() -> None:
    report = json.loads(_CURRENT_REPORT.read_text(encoding="utf-8"))
    raw_hash = hashlib.sha256(_CURRENT_RAW_REPORT.read_bytes()).hexdigest()

    expect(
        report["commit"] == "04e2f5b4a365154712149ddc0f668d4b7692d495"
        and report["provenance"] == "local-source-tree"
        and report["campaign_report_sha256"] == raw_hash
    )


def test_current_local_fuzz_campaign_passes_each_declared_target() -> None:
    report = json.loads(_CURRENT_REPORT.read_text(encoding="utf-8"))

    expect(
        report["status"] == "passed"
        and report["failure_count"] == 0
        and set(report["target_runs"]) == _EXPECTED_TARGETS
        and all(report["target_runs"][target] == _CASES_PER_TARGET for target in _EXPECTED_TARGETS)
        and sum(report["target_runs"].values()) == _TOTAL_TARGET_RUNS
        and report["parser_diagnostic_counts"] == {"macho_load_commands.warning": 428}
    )


def test_current_local_fuzz_campaign_does_not_expose_host_paths() -> None:
    report = _CURRENT_REPORT.read_text(encoding="utf-8") + _CURRENT_RAW_REPORT.read_text(encoding="utf-8")

    expect(not any(prefix in report for prefix in _HOST_PATH_PREFIXES))


def test_current_wheel_fuzz_campaign_binds_summary_to_workflow_artifact() -> None:
    report = json.loads(_WHEEL_REPORT.read_text(encoding="utf-8"))
    raw_hash = hashlib.sha256(_WHEEL_RAW_REPORT.read_bytes()).hexdigest()

    expect(
        report["commit"] == "8d6ceb6a7f90cb39bc47c4bd9c4b36b14d758e31"
        and report["workflow_run"] == _WHEEL_WORKFLOW_RUN
        and report["provenance"] == "github-actions-installed-wheel"
        and report["campaign_report_sha256"] == raw_hash
    )


def test_current_wheel_fuzz_campaign_passes_each_declared_target() -> None:
    report = json.loads(_WHEEL_REPORT.read_text(encoding="utf-8"))

    expect(
        report["status"] == "passed"
        and report["failure_count"] == 0
        and set(report["target_runs"]) == _EXPECTED_TARGETS
        and all(report["target_runs"][target] == _CASES_PER_TARGET for target in _EXPECTED_TARGETS)
        and sum(report["target_runs"].values()) == _TOTAL_TARGET_RUNS
        and report["parser_diagnostic_counts"] == {"macho_load_commands.warning": 428}
        and report["runtime"]
        == {
            "os": "ubuntu-latest",
            "python": "3.12",
            "package_source": "installed-wheel",
        }
    )


def test_current_wheel_fuzz_campaign_does_not_expose_host_paths() -> None:
    report = _WHEEL_REPORT.read_text(encoding="utf-8") + _WHEEL_RAW_REPORT.read_text(encoding="utf-8")

    expect(not any(prefix in report for prefix in _HOST_PATH_PREFIXES))
