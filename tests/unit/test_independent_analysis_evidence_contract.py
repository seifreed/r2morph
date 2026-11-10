"""Regression checks for bounded independent-analysis evidence artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs" / "protection-independent-analysis-2026-11-10.json"
_EXPECTED_PROTECTED_FUNCTION_COUNT = 2


def _report() -> dict[str, Any]:
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


def test_independent_analysis_report_binds_to_the_checked_in_fixture() -> None:
    report = _report()
    fixture = _ROOT / report["fixture"]["path"]
    fixture_sha256 = hashlib.sha256(fixture.read_bytes()).hexdigest()

    expect(fixture_sha256 == report["fixture"]["sha256"] == report["original"]["sha256"])


def test_independent_analysis_report_keeps_the_observation_fixture_bounded() -> None:
    report = _report()

    expect(
        report["measurement"] == "targeted-independent-static-analysis-pair"
        and report["original"]["function_count"] == 1
        and report["protected"]["function_count"] == _EXPECTED_PROTECTED_FUNCTION_COUNT
    )


def test_independent_analysis_report_does_not_claim_runtime_or_general_resistance() -> None:
    report = _report()

    expect(
        report["runtime_equivalence"] == "not measured"
        and any("does not establish general resistance" in item for item in report["limitations"])
    )
