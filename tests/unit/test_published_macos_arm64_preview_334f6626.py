"""Checks the current wheel-backed macOS ARM64 preview evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = _ROOT / "docs/protection-platform-macos-arm64-2026-11-14-334f6626.json"
_REPORT_PATH = _ROOT / "docs/protection-platform-macos-arm64-2026-11-14-334f6626.xml"
_SOURCE_COMMIT = "334f6626a38bfdbf933ecaf5afdc4312a6d61d98"
_SHA256_HEX_LENGTH = 64
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY_PATH.read_text(encoding="utf-8"))


def _counts() -> dict[str, int]:
    root = ElementTree.parse(_REPORT_PATH).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    return {
        key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }


def test_macos_arm64_preview_summary_binds_wheel_run_to_source_commit() -> None:
    summary = _summary()

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["execution"] == "installed-wheel"
        and summary["report_sha256"] == hashlib.sha256(_REPORT_PATH.read_bytes()).hexdigest()
        and len(summary["package"]["sha256"]) == _SHA256_HEX_LENGTH
    )


def test_macos_arm64_preview_junit_has_no_failures_or_skips() -> None:
    expect(_counts() == {"tests": 35, "failures": 0, "errors": 0, "skipped": 0})


def test_macos_arm64_preview_keeps_cross_platform_parity_open() -> None:
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence = readiness["criteria"]["cross_platform_parity"]["evidence"]

    expect(
        readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and f"docs/{_SUMMARY_PATH.name}" in evidence
        and f"docs/{_REPORT_PATH.name}" in evidence
    )


def test_macos_arm64_preview_report_redacts_host_identity_and_paths() -> None:
    content = _SUMMARY_PATH.read_text(encoding="utf-8") + _REPORT_PATH.read_text(encoding="utf-8")

    expect(
        "redacted" in content
        and "SkynetOS.local" not in content
        and not any(prefix in content for prefix in _HOST_PATH_PREFIXES)
    )
