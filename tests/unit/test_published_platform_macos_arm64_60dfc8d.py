"""Contract checks for the current-main wheel-backed macOS ARM64 preview."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-platform-macos-arm64-2026-11-14-60dfc8d.json"
_REPORT_PATH = _ROOT / "docs/protection-platform-macos-arm64-2026-11-14-60dfc8d.xml"
_SOURCE_COMMIT = "60dfc8da7fa4489a9d99e96e39a47697cb46165c"
_EXPECTED_COUNTS = {"tests": 35, "failures": 0, "errors": 0, "skipped": 0}
_MAX_EXPECTED_DURATION_SECONDS = 60.0
_SHA256_HEX_LENGTH = 64
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def _counts() -> dict[str, int]:
    root = ElementTree.parse(_REPORT_PATH).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    return {key: sum(int(suite.attrib.get(key, "0")) for suite in suites) for key in _EXPECTED_COUNTS}


def test_macos_arm64_preview_binds_report_and_wheel_to_source_commit() -> None:
    summary = _summary()

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["execution"] == "installed-wheel"
        and summary["platform"] == "macOS ARM64"
        and summary["report"] == _REPORT_PATH.name
        and summary["report_sha256"] == hashlib.sha256(_REPORT_PATH.read_bytes()).hexdigest()
        and len(summary["package"]["sha256"]) == _SHA256_HEX_LENGTH
    )


def test_macos_arm64_preview_records_only_passing_cases() -> None:
    summary = _summary()["summary"]

    expect(
        _counts() == _EXPECTED_COUNTS
        and {key: summary[key] for key in _EXPECTED_COUNTS} == _EXPECTED_COUNTS
        and 0 < summary["duration_seconds"] < _MAX_EXPECTED_DURATION_SECONDS
    )


def test_macos_arm64_preview_keeps_full_parity_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence = readiness["criteria"]["cross_platform_parity"]["evidence"]

    expect(
        readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and f"docs/{_SUMMARY_PATH.name}" in evidence
        and f"docs/{_REPORT_PATH.name}" in evidence
    )


def test_macos_arm64_preview_does_not_publish_analyst_host_paths() -> None:
    content = _SUMMARY_PATH.read_text(encoding="utf-8") + _REPORT_PATH.read_text(encoding="utf-8")

    expect(not any(prefix in content for prefix in _HOST_PATH_PREFIXES) and "SkynetOS.local" not in content)
