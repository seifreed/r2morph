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
_HOST_ADVERSARIAL_SHARD = "docs/protection-host-adversarial-shard-2026-11-12-2867d63b-shard-00.json"
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
_EXPECTED_DECLARED_PASSES = 22
_EXPECTED_SEED_RUNS = 23892
_EXPECTED_APPLIED_RUNS = 6939
_EXPECTED_SUPPORT_MATRIX_CELLS = 264


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


def test_readiness_tracks_host_shard_without_closing_open_criteria() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    criteria = readiness["criteria"]

    expect(
        _HOST_ADVERSARIAL_SHARD in criteria["all_named_adversarial_analyzers"]["evidence"]
        and _HOST_ADVERSARIAL_SHARD in criteria["published_resistance_results"]["evidence"]
        and criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and set(readiness["blocking_criteria"])
        == {"all_named_adversarial_analyzers", "cross_platform_parity", "published_resistance_results"}
    )


def test_readiness_tracks_thirteenth_host_shard_without_closing_open_criteria() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    criteria = readiness["criteria"]
    report = "docs/protection-host-adversarial-shard-2026-11-12-0ab74d02-shard-11.json"

    expect(
        report in criteria["all_named_adversarial_analyzers"]["evidence"]
        and report in criteria["published_resistance_results"]["evidence"]
        and criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and set(readiness["blocking_criteria"])
        == {"all_named_adversarial_analyzers", "cross_platform_parity", "published_resistance_results"}
    )


def test_readiness_tracks_current_host_shard_without_closing_open_criteria() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    criteria = readiness["criteria"]
    reports = (
        "docs/protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13.json",
        "docs/protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13-summary.json",
    )

    expect(
        all(
            report in criteria[criterion]["evidence"]
            for report in reports
            for criterion in ("all_named_adversarial_analyzers", "published_resistance_results")
        )
        and criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and set(readiness["blocking_criteria"])
        == {"all_named_adversarial_analyzers", "cross_platform_parity", "published_resistance_results"}
    )


def test_readiness_tracks_current_all_pass_host_shard_without_closing_open_criteria() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    criteria = readiness["criteria"]
    reports = (
        "docs/protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13.json",
        "docs/protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13-summary.json",
    )

    expect(
        all(
            report in criteria[criterion]["evidence"]
            for report in reports
            for criterion in ("all_named_adversarial_analyzers", "published_resistance_results")
        )
        and criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and set(readiness["blocking_criteria"])
        == {"all_named_adversarial_analyzers", "cross_platform_parity", "published_resistance_results"}
    )


def test_readiness_publishes_correctness_and_cost_for_all_declared_passes() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    core_path = _ROOT / "docs" / "protection-differential-2026-11-11-019a0551.json"
    extended_path = _ROOT / "docs" / "protection-extended-differential-2026-11-11-019a0551.json"
    core = json.loads(core_path.read_text(encoding="utf-8"))
    extended = json.loads(extended_path.read_text(encoding="utf-8"))
    criteria = readiness["criteria"]
    extended_summary = extended["summary"]

    expect(
        criteria["published_correctness_results"]["status"] == "complete"
        and criteria["published_cost_results"]["status"] == "complete"
        and "published_correctness_results" not in readiness["blocking_criteria"]
        and "published_cost_results" not in readiness["blocking_criteria"]
        and core["campaign"]["core_passes"] + extended_summary["extended_pass_count"] == _EXPECTED_DECLARED_PASSES
        and core["campaign"]["seed_runs"] + extended["corpus_scope"]["total_seed_runs"] == _EXPECTED_SEED_RUNS
        and core["campaign"]["applied_runs"] + extended_summary["applied_runs"] == _EXPECTED_APPLIED_RUNS
        and core["campaign"]["semantic_failures"] + extended_summary["semantic_failures"] == 0
        and extended_summary["runtime_observable_failures"] == 0
        and extended_summary["complete_evidence_missing_runs"] == 0
    )


def test_readiness_completes_compatibility_contract_without_claiming_parity() -> None:
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    support_matrix = json.loads((_ROOT / "docs" / "support-matrix.json").read_text(encoding="utf-8"))
    matrix = support_matrix["matrix"]
    official = support_matrix["official_target"]
    non_official_cells = [
        cell
        for cell in matrix["cells"]
        if (cell["format"], cell["architecture"]) != (official["format"], official["architecture"])
    ]
    criteria = readiness["criteria"]

    expect(
        criteria["complete_compatibility_contract"]["status"] == "complete"
        and "complete_compatibility_contract" not in readiness["blocking_criteria"]
        and criteria["cross_platform_parity"]["status"] == "open"
        and "cross_platform_parity" in readiness["blocking_criteria"]
        and matrix["cell_count"] == _EXPECTED_SUPPORT_MATRIX_CELLS
        and len(matrix["cells"]) == _EXPECTED_SUPPORT_MATRIX_CELLS
        and all(cell["support_status"] != "supported" for cell in non_official_cells)
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


def test_one_zero_gate_rejects_evidence_symlink_outside_the_readiness_root(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    external_evidence = tmp_path / "external.md"
    external_evidence.write_text("external evidence\n", encoding="utf-8")
    evidence_link = evidence_root / "evidence.md"
    evidence_link.symlink_to(external_evidence)
    report = json.loads(_READINESS.read_text(encoding="utf-8"))
    report["criteria"][_CRITERIA[0]]["evidence"] = [evidence_link.name]
    report_path = evidence_root / "readiness.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    rejected = False
    try:
        _check_one_zero_release_gate("0.4.0-alpha.3", report_path, evidence_root)
    except ValueError as error:
        rejected = "missing or unsafe" in str(error)

    expect(rejected)
