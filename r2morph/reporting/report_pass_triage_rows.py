"""Helpers for deriving pass sets from persisted triage rows."""

from __future__ import annotations

from typing import Any


def _pass_names_from_triage_rows(
    triage_rows: list[dict[str, Any]],
    *,
    kind: str,
) -> set[str]:
    """Derive pass sets from persisted triage rows when buckets are missing."""
    selected: set[str] = set()
    for row in triage_rows:
        pass_name = str(row.get("pass_name", "")).strip()
        if not pass_name:
            continue
        severity = str(row.get("severity", "not-requested"))
        structural_issue_count = int(row.get("structural_issue_count", 0))
        symbolic_mismatch = int(row.get("symbolic_binary_mismatched_regions", 0))
        symbolic_requested = int(row.get("symbolic_requested", 0))
        without_coverage = int(row.get("without_coverage", 0))
        issue_count = int(row.get("issue_count", 0))
        clean = (
            structural_issue_count == 0
            and symbolic_mismatch == 0
            and severity in {"clean", "not-requested"}
            and issue_count == 0
        )
        covered = clean and symbolic_requested > 0 and without_coverage == 0
        uncovered = clean and not covered
        symbolic_risk = (
            symbolic_mismatch > 0 or severity in {"mismatch", "without-coverage", "bounded-only"} or issue_count > 0
        )
        structural_risk = structural_issue_count > 0
        risky = symbolic_risk or structural_risk
        if (
            (kind == "risky" and risky)
            or (kind == "structural" and structural_risk)
            or (kind == "symbolic" and symbolic_risk)
            or (kind == "clean" and clean)
            or (kind == "covered" and covered)
            or (kind == "uncovered" and uncovered)
        ):
            selected.add(pass_name)
    return selected
