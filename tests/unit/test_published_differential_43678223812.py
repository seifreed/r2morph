"""Regression checks for the November 15 platform and VM evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from defusedxml import ElementTree

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_DOCS = _ROOT / "docs"
_RUN_ID = 43_678_223_812
_SOURCE_COMMIT = "0e39d3ab5c24ec9100d602986f1cac9aa54ffa88"
_PLATFORM_MANIFEST = _DOCS / "protection-platform-preview-run-2026-11-15-43678223812.json"
_VM_SUMMARY = _DOCS / "protection-vm-semantic-native-parity-2026-11-15-43678223812-summary.json"
_PLATFORM_COUNTS = {
    "elf_arm_32": 6,
    "elf_arm64": 7,
    "elf_x86_32": 8,
    "macos_arm64": 35,
    "windows_pe": 17,
}
_PLATFORM_TOTAL = 73
_VM_SEED_COUNT = 3
_VM_FIXTURE_COUNT = 1005
_ZERO = 0
_HOST_PATH_PREFIXES = (b"/Users/", b"/Applications/", b"/private/", b"/home/", b"/runner/")


def _platform_manifest() -> dict[str, object]:
    return json.loads(_PLATFORM_MANIFEST.read_text(encoding="utf-8"))


def _vm_summary() -> dict[str, object]:
    return json.loads(_VM_SUMMARY.read_text(encoding="utf-8"))


def _xml_counts(path: Path) -> dict[str, int]:
    root = ElementTree.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    return {
        name: sum(int(suite.attrib.get(name, "0")) for suite in suites)
        for name in ("tests", "failures", "errors", "skipped")
    }


def test_platform_aggregate_binds_to_successful_source_job() -> None:
    manifest = _platform_manifest()
    expect(
        manifest["workflow_run"] == _RUN_ID
        and manifest["source_commit"] == _SOURCE_COMMIT
        and manifest["current_main_runtime_source_unchanged_since_source_commit"] is True
        and manifest["aggregate_job"] == {"id": 132706356173, "conclusion": "success"}
    )


def test_platform_aggregate_hashes_all_five_reports() -> None:
    manifest = _platform_manifest()
    reports = manifest["platform_reports"]
    summary_report = manifest["summary_report"]
    expect(
        set(reports) == set(_PLATFORM_COUNTS)
        and hashlib.sha256((_DOCS / summary_report["report"]).read_bytes()).hexdigest() == summary_report["sha256"]
        and all(
            hashlib.sha256((_DOCS / row["report"]).read_bytes()).hexdigest() == row["sha256"]
            for row in reports.values()
        )
    )


def test_platform_aggregate_records_complete_required_smoke_cases() -> None:
    manifest = _platform_manifest()
    reports = manifest["platform_reports"]
    platform_summary = json.loads((_DOCS / manifest["summary_report"]["report"]).read_text(encoding="utf-8"))
    expect(
        all(
            reports[name]["tests"] == count
            and reports[name]["failures"] == reports[name]["errors"] == reports[name]["skipped"] == _ZERO
            and _xml_counts(_DOCS / reports[name]["report"])
            == {"tests": count, "failures": _ZERO, "errors": _ZERO, "skipped": _ZERO}
            for name, count in _PLATFORM_COUNTS.items()
        )
        and manifest["totals"] == {"tests": _PLATFORM_TOTAL, "failures": _ZERO, "errors": _ZERO, "skipped": _ZERO}
        and platform_summary["summary"]
        == {"complete_platforms": 5, "incomplete_platforms": [], "platform_count": 5, "status": "complete"}
    )


def test_platform_aggregate_keeps_general_parity_open() -> None:
    readiness = json.loads((_DOCS / "one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence = readiness["criteria"]["cross_platform_parity"]["evidence"]
    paths = [
        f"docs/{_PLATFORM_MANIFEST.name}",
        f"docs/{_platform_manifest()['summary_report']['report']}",
        *(f"docs/{row['report']}" for row in _platform_manifest()["platform_reports"].values()),
    ]
    expect(
        readiness["criteria"]["cross_platform_parity"]["status"] == "open" and all(path in evidence for path in paths)
    )


def test_vm_semantic_archive_is_hash_bound_to_successful_source_job() -> None:
    summary = _vm_summary()
    archive = _DOCS / summary["archive"]["path"]
    compressed = archive.read_bytes()
    uncompressed = gzip.decompress(compressed)
    expect(
        summary["workflow_run"] == _RUN_ID
        and summary["source_commit"] == _SOURCE_COMMIT
        and summary["aggregate_job"] == {"id": 132713378563, "conclusion": "success"}
        and hashlib.sha256(compressed).hexdigest() == summary["archive"]["sha256"]
        and hashlib.sha256(uncompressed).hexdigest() == summary["archive"]["uncompressed_sha256"]
        and len(uncompressed) == summary["archive"]["uncompressed_size_bytes"]
    )


def test_vm_semantic_campaign_records_all_native_fixture_pairs() -> None:
    summary = _vm_summary()
    expect(
        summary["target"] == {"architecture": "x86-64", "format": "ELF", "os": "linux"}
        and summary["seed_count"] == _VM_SEED_COUNT
        and summary["fixture_count"] == summary["passed_count"] == _VM_FIXTURE_COUNT
        and summary["failed_count"] == _ZERO
        and summary["failures"] == []
        and summary["qemu_summary"]["completed_pairs"] == _VM_FIXTURE_COUNT
        and summary["qemu_summary"]["divergent_pairs"] == _ZERO
        and summary["qemu_summary"]["missing_pairs"] == _ZERO
        and summary["qemu_summary"]["unavailable_pairs"] == _ZERO
        and all(
            capability["passed_count"] == capability["fixture_count"] and capability["failed_count"] == _ZERO
            for capability in summary["capability_summary"].values()
        )
    )


def test_vm_semantic_evidence_does_not_claim_resistance() -> None:
    readiness = json.loads((_DOCS / "one-zero-readiness.json").read_text(encoding="utf-8"))
    evidence = readiness["criteria"]["published_correctness_results"]["evidence"]
    paths = [f"docs/{_VM_SUMMARY.name}", f"docs/{_vm_summary()['archive']['path']}"]
    expect(
        readiness["criteria"]["published_correctness_results"]["status"] == "complete"
        and all(path in evidence for path in paths)
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )


def test_published_aggregates_do_not_expose_analyst_host_paths() -> None:
    manifest = _platform_manifest()
    reports = [
        _DOCS / manifest["summary_report"]["report"],
        *(_DOCS / row["report"] for row in manifest["platform_reports"].values()),
        _DOCS / _vm_summary()["archive"]["path"],
    ]
    content = b"".join(
        gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes() for path in reports
    )
    expect(not any(prefix in content for prefix in _HOST_PATH_PREFIXES))
