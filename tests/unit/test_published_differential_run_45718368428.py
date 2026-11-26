"""Pin the completed source-bound differential campaign and its limits."""

from __future__ import annotations

import gzip
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = _ROOT / "docs/differential-run-2026-11-25-45718368428.json"
_TEST_PATH = "tests/unit/test_published_differential_run_45718368428.py"
_RUN_ID = 45718368428
_SOURCE_COMMIT = "a1e0099574190f2a9a426750b8286e5bc24ab40d"
_CI_RUN_ID = 45718344391
_COMPOSITION_CASES = 46
_PUBLIC_SAMPLES = 370
_STATIC_RECOVERY_ROWS = 2220
_VM_CASES = 1005
_VM_CAPABILITY_COUNT = 9
_PLATFORM_COUNT = 6
_PLATFORM_CASES = 81


def _load_report(manifest: dict[str, Any], key: str) -> dict[str, Any]:
    entry = manifest[key]
    compressed = (_ROOT / entry["path"]).read_bytes()
    expect(hashlib.sha256(compressed).hexdigest() == entry["sha256"])
    return json.loads(gzip.decompress(compressed))


def _totals(report: dict[str, Any]) -> dict[str, int]:
    rows = list(report["summary"].values())
    return {
        "pass_count": len(rows),
        "classified_seed_runs": sum(row["complete_evidence_runs"] for row in rows),
        "applied_runs": sum(row["applied_runs"] for row in rows),
        "omitted_runs": sum(row["omitted_runs"] for row in rows),
        "error_runs": sum(row["error_runs"] for row in rows),
        "failed_seed_runs": sum(row["failed_seed_runs"] for row in rows),
        "complete_evidence_runs": sum(row["complete_evidence_runs"] for row in rows),
    }


def test_manifest_pins_current_source_and_complete_campaign_results() -> None:
    manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    core = _load_report(manifest, "core_differential")
    extended = _load_report(manifest, "extended_differential")
    maturity = _load_report(manifest, "maturity_evidence")

    expect(
        manifest["run_id"] == _RUN_ID
        and manifest["run_attempt"] == 1
        and manifest["source_commit"] == _SOURCE_COMMIT
        and manifest["conclusion"] == "success"
        and manifest["jobs"] == {"total": 86, "passed": 86, "failed": 0, "cancelled": 0}
        and manifest["ci_validation"]["run_id"] == _CI_RUN_ID
        and manifest["ci_validation"]["source_commit"] == _SOURCE_COMMIT
        and manifest["ci_validation"]["conclusion"] == "success"
        and manifest["ci_validation"]["jobs"] == {"total": 19, "passed": 19, "failed": 0, "cancelled": 0}
        and _totals(core)
        == {
            "pass_count": 10,
            "classified_seed_runs": 10860,
            "applied_runs": 3480,
            "omitted_runs": 7380,
            "error_runs": 0,
            "failed_seed_runs": 0,
            "complete_evidence_runs": 10860,
        }
        and _totals(extended)
        == {
            "pass_count": 12,
            "classified_seed_runs": 13032,
            "applied_runs": 3406,
            "omitted_runs": 9626,
            "error_runs": 0,
            "failed_seed_runs": 0,
            "complete_evidence_runs": 13032,
        }
        and maturity["summary"]["blocker_totals"]
        == {
            "affected_instructions": 0,
            "behavioral_false_positive": 0,
            "composition": 0,
            "decompiler": 22,
            "performance": 0,
        }
        and manifest["composition"]["case_count"] == _COMPOSITION_CASES
        and manifest["composition"]["failed_cases"]
        == manifest["composition"]["error_cases"]
        == manifest["composition"]["skipped_cases"]
        == 0
    )


def test_public_vm_and_platform_reports_preserve_bounded_scope() -> None:
    manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    public = _load_report(manifest, "public_compatibility")
    vm = _load_report(manifest, "vm_semantic")
    contracts = _load_report(manifest, "vm_regression_contracts")
    platform_entry = manifest["platform_preview"]
    platform_bytes = (_ROOT / platform_entry["path"]).read_bytes()
    platform = json.loads(platform_bytes)
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        hashlib.sha256(platform_bytes).hexdigest() == platform_entry["sha256"]
        and public["matrix"]["built_samples"] == public["matrix"]["passed_samples"] == _PUBLIC_SAMPLES
        and public["matrix"]["failed_samples"] == 0
        and public["static_recovery"]["measured_samples"] == _STATIC_RECOVERY_ROWS
        and public["static_recovery"]["failed_samples"] == 0
        and public["static_recovery"]["analyzer"] == "radare2"
        and all(runner["status"] == "omitted" for runner in public["static_recovery"]["optional_runners"].values())
        and vm["status"] == "passed"
        and vm["passed_count"] == vm["qemu_summary"]["completed_pairs"] == _VM_CASES
        and vm["qemu_summary"]["divergent_pairs"] == vm["qemu_summary"]["missing_pairs"] == 0
        and len(contracts["capabilities"]) == _VM_CAPABILITY_COUNT
        and all(item["status"] == "regression-covered" for item in contracts["capabilities"].values())
        and platform_entry["platform_count"] == _PLATFORM_COUNT
        and platform_entry["case_count"] == platform_entry["passed_cases"] == _PLATFORM_CASES
        and platform_entry["failed_cases"] == platform_entry["error_cases"] == platform_entry["skipped_cases"] == 0
        and sum(item["case_count"] for item in platform["platforms"].values()) == _PLATFORM_CASES
        and all(
            item["failure_count"] == item["error_count"] == item.get("skipped_count", 0) == 0
            and not item["missing_required_cases"]
            for item in platform["platforms"].values()
        )
    )

    xml_entry = manifest["composition"]
    xml_bytes = (_ROOT / xml_entry["path"]).read_bytes()
    expect(hashlib.sha256(xml_bytes).hexdigest() == xml_entry["sha256"])
    # The local XML report is pinned by SHA-256 above before parsing.
    suite = ET.fromstring(xml_bytes).find("testsuite")  # noqa: S314
    expect(suite is not None)

    criteria = readiness["criteria"]
    manifest_path = _MANIFEST_PATH.relative_to(_ROOT).as_posix()
    expect(
        criteria["complete_compatibility_contract"]["status"] == "complete"
        and criteria["published_correctness_results"]["status"] == "complete"
        and criteria["cross_platform_parity"]["status"] == "open"
        and criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and manifest_path in criteria["published_correctness_results"]["evidence"]
        and _TEST_PATH in criteria["published_correctness_results"]["evidence"]
        and manifest_path in criteria["cross_platform_parity"]["evidence"]
        and _TEST_PATH in criteria["cross_platform_parity"]["evidence"]
        and manifest_path in criteria["all_named_adversarial_analyzers"]["evidence"]
        and _TEST_PATH in criteria["all_named_adversarial_analyzers"]["evidence"]
    )


def test_github_artifact_archives_are_pinned_by_digest() -> None:
    manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    archives = {entry["id"]: entry["digest"] for entry in manifest["artifact_archives"]}
    expect(
        archives
        == {
            15073491821: "sha256:87e8cca8008f3ff297def4b8942cd1ced52cb615dbfd174dd11451a9fbd3d816",
            15072698202: "sha256:0754fbd4c725fa28a8784f6ab104cd2f444bc5f82efe6b5836fadcb619691c0f",
            15072118954: "sha256:48343b1a3f86bc0809f369357d7bdfee6f3b7c953bbb0a6bbc315828a54e6919",
            15072462906: "sha256:fcd7b167aedbcec32e9340ca5c93b44469ef6d8c5ef5674f8ac286c8a15ddc48",
            15073245384: "sha256:737808b0adb17b95e8c5ad9795a1a05dea4896fcf9645e6610a43d78972d2fe0",
            15072362267: "sha256:ba0e1aedd60d6e259352ce95e8b1b532b952b27bb2f3f00e7f61fe21e68f948e",
            15072396508: "sha256:4edb359251523eeeae7a578da6d7b2535080be453b60a2dc41fa79e549f08fb9",
            15071993621: "sha256:63f44497328d5b89d921c204c925c8ed6ee83cb88f2b8acda58df8cd7862e3df",
        }
    )
