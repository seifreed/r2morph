"""Verify the hash-bound six-slice platform preview evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree as DefusedElementTree  # type: ignore[import-untyped]

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs/protection-platform-preview-2026-11-24-45480009561.json"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_RUN_ID = 45480009561
_SOURCE_COMMIT = "a4f4dcba12020cda4fa7717c4361c027d4b09081"
_EXPECTED = {
    "macos-arm64": (
        138750290831,
        14960324112,
        "cross-platform-differential-macos-arm64-45480009561-1",
        "docs/platform-smoke-45480009561-macos-arm64.xml",
        "fb7ee9d1afa10e3dadf282bd88b3b5b4db8fdd36ee2f1c58f193906505bf67de",
        36,
    ),
    "macos-x86-64": (
        138750290310,
        14961598946,
        "cross-platform-differential-macos-x86-64-45480009561-1",
        "docs/protection-macho-x86-64-native-2026-11-24-a4f4dcba.xml",
        "e87941f1cb29a915bf41612944cee7dcf3e2045caaf3e35a82eb9518caaa25f1",
        3,
    ),
    "windows-pe": (
        138750290829,
        14961627731,
        "cross-platform-differential-windows-pe-45480009561-1",
        "docs/platform-smoke-45480009561-windows-pe.xml",
        "739caa0f744e469e948451041912f88a53bde7914444f22ca76a9521f7eb9b6c",
        18,
    ),
    "elf-arm32": (
        138750291252,
        14959919135,
        "elf-arm-32-native-45480009561-1",
        "docs/platform-smoke-45480009561-elf-arm32.xml",
        "904a23575ec6fdf99e8a1e14216236033ccc38ed6e34940049d44a27625dce0c",
        6,
    ),
    "elf-arm64": (
        138750290837,
        14962155975,
        "elf-arm64-native-45480009561-1",
        "docs/platform-smoke-45480009561-elf-arm64.xml",
        "00cfd96cac5fbe8336444bc83728c6c806daa1f4b1ed9e7e5ff65298780d966d",
        7,
    ),
    "elf-x86-32": (
        138750291354,
        14961862866,
        "elf-x86-32-native-45480009561-1",
        "docs/platform-smoke-45480009561-elf-x86-32.xml",
        "b05c9cab60ab0e92014fe92775c4b35fbd68e513d2e8eef9bca3c27a30b03e5d",
        8,
    ),
}
_TOTAL_CASES = 78


def test_platform_preview_manifest_binds_current_workflow_and_artifacts() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    rows = {row["target"]: row for row in report["reports"]}

    expect(
        report["source_commit"] == _SOURCE_COMMIT
        and report["workflow"]["run_id"] == _RUN_ID
        and set(rows) == set(_EXPECTED)
        and all(
            (
                rows[target]["job_id"],
                rows[target]["artifact_id"],
                rows[target]["artifact_name"],
                rows[target]["junit_path"],
                rows[target]["junit_sha256"],
                rows[target]["case_count"],
            )
            == expected
            for target, expected in _EXPECTED.items()
        )
    )


def test_platform_preview_junit_reports_have_no_failures_or_skips() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    observed_total = 0

    for row in report["reports"]:
        junit_path = _ROOT / row["junit_path"]
        expect(hashlib.sha256(junit_path.read_bytes()).hexdigest() == row["junit_sha256"])
        suites = list(DefusedElementTree.parse(junit_path).getroot().iter("testsuite"))
        cases = [case for suite in suites for case in suite.iter("testcase")]
        observed_total += len(cases)
        expect(
            len(suites) == 1
            and len(cases) == row["case_count"]
            and len({case.attrib.get("name") for case in cases}) == len(cases)
            and all(
                suite.attrib.get("failures") == "0"
                and suite.attrib.get("errors") == "0"
                and suite.attrib.get("skipped") == "0"
                for suite in suites
            )
            and not any(case.find("failure") is not None for case in cases)
            and not any(case.find("error") is not None for case in cases)
            and not any(case.find("skipped") is not None for case in cases)
        )

    summary = report["summary"]
    expect(
        observed_total == _TOTAL_CASES
        and summary["platform_slices"] == len(_EXPECTED)
        and summary["case_count"] == summary["passed_case_count"] == _TOTAL_CASES
        and summary["failed_case_count"] == summary["error_case_count"] == summary["skipped_case_count"] == 0
    )


def test_platform_preview_keeps_cross_platform_parity_gate_open() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    criterion = readiness["criteria"]["cross_platform_parity"]

    expect(
        criterion["status"] == "open"
        and _REPORT.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and Path(__file__).relative_to(_ROOT).as_posix() in criterion["evidence"]
        and report["limitations"]
    )
