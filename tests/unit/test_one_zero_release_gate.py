"""Regression tests for the stable-major evidence gate."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scripts.check_release_contract import _check_one_zero_release_gate
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_READINESS = _ROOT / "docs" / "one-zero-readiness.json"
_PASS_MATURITY = _ROOT / "docs" / "pass-maturity.md"
_RELEASE_BLOCKERS = _ROOT / "docs" / "release-blockers.md"
_CRITERIA = (
    "all_named_adversarial_analyzers",
    "complete_compatibility_contract",
    "cross_platform_parity",
    "documented_resistance_scope",
    "published_cost_results",
    "published_correctness_results",
    "published_resistance_results",
    "stable_api_cli",
)


def test_one_zero_gate_allows_alpha_while_readiness_is_open() -> None:
    expect(_check_one_zero_release_gate("0.4.0-alpha.3", _READINESS, _ROOT) is None)


def test_one_zero_gate_blocks_stable_major_with_open_readiness() -> None:
    rejected = False
    try:
        _check_one_zero_release_gate("1.0.0", _READINESS, _ROOT)
    except ValueError as error:
        rejected = "blocked by incomplete 1.0 criteria" in str(error)

    expect(rejected)


def test_readiness_keeps_general_resistance_results_open_when_scope_is_documented() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    pass_maturity = " ".join(_PASS_MATURITY.read_text(encoding="utf-8").split())
    release_blockers = " ".join(_RELEASE_BLOCKERS.read_text(encoding="utf-8").split())
    criteria = readiness["criteria"]

    expect(
        criteria["documented_resistance_scope"]["status"] == "complete"
        and criteria["published_resistance_results"]["status"] == "open"
        and "published_resistance_results" in readiness["blocking_criteria"]
        and "does not establish general resistance to professional reverse engineering" in pass_maturity
        and "close the 1.0 `published_resistance_results` criterion" in pass_maturity
        and "does not establish general resistance to professional reverse engineering" in release_blockers
    )


def test_one_zero_gate_accepts_complete_linked_evidence(tmp_path: Path) -> None:
    criteria: dict[str, Any] = {}
    for name in _CRITERIA:
        evidence_path = tmp_path / f"{name}.md"
        evidence_path.write_text("verified evidence\n", encoding="utf-8")
        criteria[name] = {"status": "complete", "evidence": [evidence_path.name]}
    report = {
        "schema_version": 1,
        "status": "ready",
        "blocking_criteria": [],
        "criteria": criteria,
    }
    report_path = tmp_path / "readiness.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    expect(_check_one_zero_release_gate("1.0.0", report_path, tmp_path) is None)


def test_one_zero_gate_rejects_evidence_paths_outside_the_readiness_root(tmp_path: Path) -> None:
    report = json.loads(_READINESS.read_text(encoding="utf-8"))
    report["criteria"][_CRITERIA[0]]["evidence"] = ["../outside.md"]
    report_path = tmp_path / "readiness.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    rejected = False
    try:
        _check_one_zero_release_gate("0.4.0-alpha.3", report_path, tmp_path)
    except ValueError as error:
        rejected = "missing or unsafe" in str(error)

    expect(rejected)
