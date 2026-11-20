"""Pin successful bounded differential evidence to its workflow artifact."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/differential-run-2026-11-20-44676092171-summary.json"
_RUN_ID = 44_676_092_171
_SOURCE_COMMIT = "2f54c47ee08dee65a2aeda406ee4bd8a3a78bbfc"
_JOB_COUNT = 86
_ARTIFACT_ID = 14_605_656_207
_CORE_RUNS = 10_860
_EXTENDED_RUNS = 13_032
_COMPATIBILITY_SAMPLES = 360
_COMPATIBILITY_PASS_COUNT = 6
_COMPOSITION_PAIRS = 44
_COMPOSITION_CASES = 2_208
_OPEN_CRITERIA = (
    "all_named_adversarial_analyzers",
    "cross_platform_parity",
    "published_resistance_results",
)


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY.read_text(encoding="utf-8")))


def test_workflow_completed_successfully_on_the_pinned_source() -> None:
    summary = _summary()
    workflow = summary["workflow"]
    artifact = summary["merged_artifact"]

    expect(
        workflow["run_id"] == _RUN_ID
        and workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["status"] == "completed"
        and workflow["conclusion"] == "success"
        and workflow["jobs_completed"] == _JOB_COUNT
        and artifact["id"] == _ARTIFACT_ID
        and artifact["sha256"] == "sha256:8b0d434341558e6d884e9ccca7a3d3174ad524aefcfd188a03e85d559e32e0cc"
    )


def test_core_and_extended_campaigns_have_complete_evidence_without_failures() -> None:
    summary = _summary()
    core = summary["differential_corpus"]
    extended = summary["extended_maturity"]

    expect(
        core["classified_runs"] == core["successful_runs"] == _CORE_RUNS
        and core["failed_runs"] == core["error_runs"] == core["complete_evidence_missing_runs"] == 0
        and core["applied_runs"] + core["omitted_ineligible_runs"] == core["classified_runs"]
        and extended["classified_runs"] == extended["successful_runs"] == _EXTENDED_RUNS
        and extended["failed_runs"] == extended["error_runs"] == extended["complete_evidence_missing_runs"] == 0
        and extended["applied_runs"] + extended["omitted_ineligible_runs"] == extended["classified_runs"]
    )


def test_compatibility_and_composition_counts_are_pinned_and_gates_remain_open() -> None:
    summary = _summary()
    compatibility = summary["supplemental_campaigns"]["public_compatibility"]
    composition = summary["supplemental_campaigns"]["composition"]
    readiness = json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8"))

    expect(
        compatibility["samples"] == compatibility["passed_samples"] == _COMPATIBILITY_SAMPLES
        and compatibility["failed_samples"] == 0
        and len(compatibility["passes"]) == _COMPATIBILITY_PASS_COUNT
        and composition["directional_pairs"] == _COMPOSITION_PAIRS
        and composition["cases"] == _COMPOSITION_CASES
        and composition["failures"] == composition["errors"] == 0
        and all(summary["release_criteria"][criterion] == "open" for criterion in _OPEN_CRITERIA)
        and all(readiness["criteria"][criterion]["status"] == "open" for criterion in _OPEN_CRITERIA)
    )
