"""Classification and triage helpers for reporting."""

from typing import Any

from r2morph.reporting.report_pass_triage_rows import _pass_names_from_triage_rows as _pass_names_from_triage_rows


def _is_risky_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass has issues worth prioritizing in triage views."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if int(evidence_summary.get("symbolic_binary_mismatched_regions", 0)) > 0:
        return True
    if int(evidence_summary.get("structural_issue_count", 0)) > 0:
        return True
    if str(symbolic_summary.get("severity", "not-requested")) in {
        "mismatch",
        "without-coverage",
        "bounded-only",
    }:
        return True
    return int(symbolic_summary.get("issue_count", 0)) > 0


def _is_covered_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass is clean and has effective symbolic coverage."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if not _is_clean_pass(evidence_summary, symbolic_summary):
        return False
    if int(symbolic_summary.get("symbolic_requested", 0)) <= 0:
        return False
    if int(symbolic_summary.get("without_coverage", 0)) > 0:
        return False
    return int(evidence_summary.get("symbolic_binary_regions_checked", 0)) > 0


def _is_uncovered_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass is clean but lacks effective symbolic coverage."""
    return _is_clean_pass(evidence_summary, symbolic_summary) and not _is_covered_pass(
        evidence_summary, symbolic_summary
    )


def _is_clean_pass(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass is clean enough for positive triage views."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if int(evidence_summary.get("structural_issue_count", 0)) > 0:
        return False
    if int(evidence_summary.get("symbolic_binary_mismatched_regions", 0)) > 0:
        return False
    severity = str(symbolic_summary.get("severity", "not-requested"))
    if severity not in {"clean", "not-requested"}:
        return False
    return int(symbolic_summary.get("issue_count", 0)) == 0


def _has_symbolic_risk(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None,
) -> bool:
    """Return True when a pass has symbolic evidence worth triaging."""
    evidence_summary = evidence_summary or {}
    symbolic_summary = symbolic_summary or {}
    if int(evidence_summary.get("symbolic_binary_mismatched_regions", 0)) > 0:
        return True
    if str(symbolic_summary.get("severity", "not-requested")) in {
        "mismatch",
        "without-coverage",
        "bounded-only",
    }:
        return True
    return int(symbolic_summary.get("issue_count", 0)) > 0


def _has_structural_risk(
    evidence_summary: dict[str, Any] | None,
    symbolic_summary: dict[str, Any] | None = None,
) -> bool:
    """Return True when a pass has structural evidence worth triaging."""
    evidence_summary = evidence_summary or {}
    return int(evidence_summary.get("structural_issue_count", 0)) > 0

