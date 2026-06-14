"""Pure data helper functions for report generation.

Predicates, utilities, and data transformations with no CLI/rendering dependencies.

Report helpers: small helper/predicate functions for reporting.
Extracted from cli.py -- no logic changes.
"""

from typing import Any

from rich.console import Console

from r2morph.reporting.report_evidence_sorting import (
    _sort_pass_evidence as _sort_pass_evidence,
)
from r2morph.reporting.report_helpers_classification import (  # noqa: F401
    _has_structural_risk,
    _has_symbolic_risk,
    _is_clean_pass,
    _is_covered_pass,
    _is_risky_pass,
    _is_uncovered_pass,
    _pass_names_from_triage_rows,
)
from r2morph.reporting.report_helpers_symbolic_view import (
    _summarize_symbolic_view_from_mutations as _summarize_symbolic_view_from_mutations,
)
from r2morph.reporting.report_mutation_selection import (
    _select_report_mutations as _select_report_mutations,
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


def _normalized_pass_map(
    normalized_pass_results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index normalized per-pass rows by pass name."""
    return {str(row.get("pass_name")): dict(row) for row in normalized_pass_results if row.get("pass_name")}
