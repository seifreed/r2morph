"""Report filtering façade for legacy public API compatibility.

The actual filtering and state-resolution logic lives in
`r2morph.reporting.report_state` and `r2morph.reporting.report_helpers`.
This module keeps the historical class-based surface small and stable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from r2morph.reporting.report_helpers import _select_report_mutations
from r2morph.reporting.report_pass_filters import resolve_pass_filter_sets as _resolve_pass_filter_sets
from r2morph.reporting.report_state import resolve_mismatch_view as _resolve_mismatch_view


@dataclass
class PassFilterSets:
    """Resolved pass filter sets for report filtering."""

    risky: set[str]
    structural: set[str]
    symbolic: set[str]
    clean: set[str]
    covered: set[str]
    uncovered: set[str]

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "risky": sorted(self.risky),
            "structural": sorted(self.structural),
            "symbolic": sorted(self.symbolic),
            "clean": sorted(self.clean),
            "covered": sorted(self.covered),
            "uncovered": sorted(self.uncovered),
        }


class PassFilterResolver:
    """Resolve pass filter buckets from persisted summary first, then fall back."""

    @staticmethod
    def resolve(summary: dict[str, Any], pass_results: dict[str, Any]) -> dict[str, set[str]]:
        return _resolve_pass_filter_sets(summary=summary, pass_results=pass_results)


class ReportFilters:
    """Handles report mutation and view filtering."""

    @staticmethod
    def select_report_mutations(
        all_mutations: list[dict[str, Any]],
        degraded_validation: bool,
        failed_gates: bool,
        only_degraded: bool,
        only_failed_gates: bool,
        only_risky_filters: bool,
        selected_risk_pass_names: set[str],
        resolved_only_pass: str | None,
        only_status: str | None,
        degraded_passes: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return _select_report_mutations(
            all_mutations=all_mutations,
            degraded_validation=degraded_validation,
            failed_gates=failed_gates,
            only_degraded=only_degraded,
            only_failed_gates=only_failed_gates,
            only_risky_filters=only_risky_filters,
            selected_risk_pass_names=selected_risk_pass_names,
            resolved_only_pass=resolved_only_pass,
            only_status=only_status,
            degraded_passes=degraded_passes,
        )

    @staticmethod
    def resolve_mismatch_view(
        summary: dict[str, Any],
        mutations: list[dict[str, Any]],
    ) -> tuple[dict[str, int], dict[str, list[str]], list[dict[str, Any]]]:
        return _resolve_mismatch_view(summary=summary, mutations=mutations)
