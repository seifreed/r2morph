"""Contracts for published differential campaign evidence."""

from __future__ import annotations

import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-differential-2026-11-11-019a0551.json"
_EXPECTED_SEED_RUN_COUNT = 10860
_EXPECTED_APPLIED_RUN_COUNT = 3565
_EXPECTED_GENERATED_FIXTURE_COUNT = 200
_EXPECTED_PUBLIC_SAMPLE_COUNT = 360
_EXPECTED_STATIC_MEASUREMENT_COUNT = 2160


def test_differential_evidence_records_complete_core_campaign() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    campaign = report["campaign"]

    expect(
        {
            key: campaign[key]
            for key in (
                "extended_passes",
                "error_runs",
                "semantic_failures",
                "runtime_observable_failures",
                "core_passes",
                "expected_core_passes",
                "seed_runs",
                "applied_runs",
                "generated_fixtures",
            )
        }
        == {
            "extended_passes": 0,
            "error_runs": 0,
            "semantic_failures": 0,
            "runtime_observable_failures": 0,
            "core_passes": 10,
            "expected_core_passes": 10,
            "seed_runs": _EXPECTED_SEED_RUN_COUNT,
            "applied_runs": _EXPECTED_APPLIED_RUN_COUNT,
            "generated_fixtures": _EXPECTED_GENERATED_FIXTURE_COUNT,
        }
    )


def test_differential_evidence_records_failure_free_public_matrix() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    matrix = report["public_compatibility"]

    expect(
        matrix["samples"] == _EXPECTED_PUBLIC_SAMPLE_COUNT
        and matrix["failed_samples"] == 0
        and matrix["static_measurements"] == _EXPECTED_STATIC_MEASUREMENT_COUNT
        and matrix["static_failures"] == 0
        and all(result["differential_failed"] == result["errors"] == 0 for result in matrix["passes"].values())
    )
