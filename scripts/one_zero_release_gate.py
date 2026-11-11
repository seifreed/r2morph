"""Gate stable-major releases on explicit, linked 1.0 evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REQUIRED_CRITERIA = {
    "cross_platform_parity",
    "all_named_adversarial_analyzers",
    "documented_resistance_scope",
    "stable_api_cli",
    "complete_compatibility_contract",
    "published_correctness_results",
    "published_cost_results",
    "published_resistance_results",
}
_VALID_CRITERION_STATUSES = {"open", "in_progress", "complete"}


def check_one_zero_release_gate(version: str, readiness_path: Path, evidence_root: Path) -> None:
    """Reject a stable-major package version until its evidence ledger is complete."""
    report = json.loads(readiness_path.read_text(encoding="utf-8"))
    criteria = report.get("criteria")
    if report.get("schema_version") != 1 or not isinstance(criteria, dict):
        raise ValueError("1.0 readiness report has an invalid schema")
    if set(criteria) != _REQUIRED_CRITERIA:
        raise ValueError("1.0 readiness report must include every required criterion")

    blockers = _validate_criteria(criteria, evidence_root)
    expected_status = "blocked" if blockers else "ready"
    if report.get("status") != expected_status or report.get("blocking_criteria") != blockers:
        raise ValueError("1.0 readiness status must match its criterion evidence")

    major = int(version.split(".", 1)[0])
    if major >= 1 and blockers:
        raise ValueError(f"stable-major release blocked by incomplete 1.0 criteria: {', '.join(blockers)}")


def _validate_criteria(criteria: dict[str, Any], evidence_root: Path) -> list[str]:
    blockers: list[str] = []
    for name in sorted(_REQUIRED_CRITERIA):
        criterion = criteria[name]
        if not isinstance(criterion, dict) or criterion.get("status") not in _VALID_CRITERION_STATUSES:
            raise ValueError(f"1.0 readiness criterion has an invalid status: {name}")
        evidence = criterion.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError(f"1.0 readiness criterion needs linked evidence: {name}")
        _validate_evidence_paths(name, evidence, evidence_root)
        if criterion["status"] != "complete":
            blockers.append(name)
    return blockers


def _validate_evidence_paths(name: str, evidence: list[Any], evidence_root: Path) -> None:
    resolved_root = evidence_root.resolve()
    for reference in evidence:
        if not isinstance(reference, str) or not reference.strip():
            raise ValueError(f"1.0 readiness criterion has an invalid evidence path: {name}")
        path = Path(reference)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"1.0 readiness evidence file is missing or unsafe: {name}: {reference}")
        try:
            resolved_path = (evidence_root / path).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"1.0 readiness evidence file is missing or unsafe: {name}: {reference}") from exc
        if not resolved_path.is_relative_to(resolved_root) or not resolved_path.is_file():
            raise ValueError(f"1.0 readiness evidence file is missing or unsafe: {name}: {reference}")
