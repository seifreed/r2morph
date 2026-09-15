#!/usr/bin/env python3
"""Summarize cross-platform JUnit evidence without hiding incomplete targets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import defusedxml.ElementTree

_REQUIRED_CASES = {
    "macos-arm64": "test_nop_insertion_arm64_preserves_native_output",
    "windows-pe": "test_pe_handler_checksum",
    "elf-arm64": "test_elf_arm64_nop_insertion_preserves_native_exit_code",
}


def _report_summary(path: Path, required_case: str) -> dict[str, Any]:
    root = defusedxml.ElementTree.parse(path).getroot()
    cases = root.findall(".//testcase")
    names = [case.attrib.get("name", "") for case in cases]
    failures = len(root.findall(".//failure"))
    errors = len(root.findall(".//error"))
    skipped = len(root.findall(".//skipped"))
    required_present = any(name.startswith(required_case) for name in names)
    complete = not failures and not errors and not skipped and required_present and bool(cases)
    return {
        "report": path.name,
        "case_count": len(cases),
        "failure_count": failures,
        "error_count": errors,
        "skipped_count": skipped,
        "required_case": required_case,
        "required_case_present": required_present,
        "status": "complete" if complete else "incomplete",
    }


def summarize_platform_reports(root: Path) -> dict[str, Any]:
    """Build a bounded summary for the declared cross-platform smoke targets."""
    platforms: dict[str, dict[str, Any]] = {}
    for platform_name, required_case in _REQUIRED_CASES.items():
        reports = sorted((root / platform_name).glob("*.xml"))
        if len(reports) != 1:
            platforms[platform_name] = {
                "report": None,
                "case_count": 0,
                "failure_count": 0,
                "error_count": 0,
                "skipped_count": 0,
                "required_case": required_case,
                "required_case_present": False,
                "status": "incomplete",
                "missing_report_count": len(reports),
            }
            continue
        platforms[platform_name] = _report_summary(reports[0], required_case)
    incomplete = sorted(name for name, report in platforms.items() if report["status"] != "complete")
    return {
        "schema_version": 1,
        "measurement": "cross-platform-differential-smoke",
        "platforms": platforms,
        "summary": {
            "platform_count": len(platforms),
            "complete_platforms": len(platforms) - len(incomplete),
            "incomplete_platforms": incomplete,
            "status": "complete" if not incomplete else "incomplete",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = summarize_platform_reports(args.root)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
