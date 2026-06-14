"""Pure data helper functions for report generation.

Predicates, utilities, and data transformations with no CLI/rendering dependencies.

Report helpers: small helper/predicate functions for reporting.
Extracted from cli.py -- no logic changes.
"""

from typing import Any

from rich.console import Console

from r2morph.core.report_helpers_indexing import _index_rows_by_pass_name
from r2morph.reporting.report_evidence_sorting import (
    _sort_pass_evidence as _sort_pass_evidence,
)
from r2morph.reporting.report_helpers_symbolic_view import (
    _summarize_symbolic_view_from_mutations as _summarize_symbolic_view_from_mutations,
)
from r2morph.reporting.report_mutation_selection import (
    _select_report_mutations as _select_report_mutations,
)
from r2morph.reporting.report_pass_classification import (  # noqa: F401
    _has_structural_risk,
    _has_symbolic_risk,
    _is_clean_pass,
    _is_covered_pass,
    _is_risky_pass,
    _is_uncovered_pass,
)
from r2morph.reporting.report_summary_lookup import _summary_first as _summary_first_impl

console = Console()


def _summary_first(
    summary: dict[str, Any],
    key: str,
    fallback: Any,
) -> Any:
    return _summary_first_impl(summary, key, fallback)


def _visible_rows(
    rows: list[dict[str, Any]],
    visible_passes: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter row-shaped report data by visible pass names."""
    if not visible_passes:
        return [dict(row) for row in rows if row.get("pass_name")]
    return [dict(row) for row in rows if row.get("pass_name") and str(row.get("pass_name")) in visible_passes]


def _visible_rows_from_map(
    source_map: dict[str, Any],
    visible_passes: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter pass-keyed map rows by visible pass names, returning dict copies."""
    if not visible_passes:
        return [dict(row) for row in source_map.values()]
    return [dict(row) for pass_name, row in source_map.items() if pass_name in visible_passes]


def _normalized_pass_map(
    normalized_pass_results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index normalized per-pass rows by pass name."""
    return _index_rows_by_pass_name(normalized_pass_results)


def _validation_context_from_role(role: str, requested_mode: Any, effective_mode: Any) -> dict[str, Any]:
    """Build a pass validation-context dict from a role and the requested/effective modes."""
    return {
        "role": role,
        "requested_validation_mode": requested_mode,
        "effective_validation_mode": effective_mode,
        "degraded_execution": role == "executed-under-degraded-mode",
        "degradation_triggered_by_pass": role == "degradation-trigger",
    }


def _pass_evidence_from_row(pass_name: Any, row: dict[str, Any]) -> dict[str, Any]:
    """Project a normalized/general pass row into a pass-evidence dict."""
    return {
        "pass_name": pass_name,
        "changed_region_count": row.get("changed_region_count", 0),
        "changed_bytes": row.get("changed_bytes", 0),
        "structural_issue_count": row.get("structural_issue_count", 0),
        "symbolic_binary_mismatched_regions": row.get("symbolic_binary_mismatched_regions", 0),
    }


def _symbolic_summary_from_normalized_row(pass_name: str, normalized_row: dict[str, Any]) -> dict[str, Any]:
    """Project a normalized per-pass row into a symbolic-summary dict."""
    return {
        "pass_name": pass_name,
        "severity": normalized_row.get("severity", "not-requested"),
        "issue_count": normalized_row.get("issue_count", 0),
        "symbolic_requested": normalized_row.get("symbolic_requested", 0),
        "observable_match": normalized_row.get("observable_match", 0),
        "observable_mismatch": normalized_row.get("observable_mismatch", 0),
        "bounded_only": normalized_row.get("bounded_only", 0),
        "without_coverage": normalized_row.get("without_coverage", 0),
        "issues": [],
    }
