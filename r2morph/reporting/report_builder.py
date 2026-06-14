"""
Report builder logic extracted from cli.py and engine.py.

This module handles building report payloads, context resolution,
and filtered report generation.
"""

from typing import Any

from r2morph.reporting.filtered_summary_builder import (
    _build_only_mismatches_payload as _build_only_mismatches_payload_impl,
)
from r2morph.reporting.filtered_summary_builder import (
    _build_report_filters as _build_report_filters_impl,
)
from r2morph.reporting.report_context_gate_state import (
    _resolve_failed_gates_view as _resolve_failed_gates_view_impl,
)
from r2morph.reporting.report_context_resolver import (
    _resolve_report_gate_state as _resolve_report_gate_state_impl,
)
from r2morph.reporting.report_gate_filters import (
    _filter_failed_gates_view as _filter_failed_gates_view_impl,
)
from r2morph.reporting.report_severity_parsing import (
    _expected_severity_rank_from_failure as _expected_severity_rank_from_failure_impl,
)


class ReportBuilder:
    """Builds report payloads and resolves report contexts."""

    @staticmethod
    def _resolve_report_gate_state(
        summary: dict[str, Any],
        payload: dict[str, Any],
        gate_evaluation: dict[str, Any],
        only_expected_severity: str | None,
        resolved_only_pass_failure: str | None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
        """Resolve persisted gate summaries and filtered gate state for report()."""
        return _resolve_report_gate_state_impl(
            summary=summary,
            payload=payload,
            gate_evaluation=gate_evaluation,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )

    @staticmethod
    def _expected_severity_rank_from_failure(failure: str) -> int:
        return _expected_severity_rank_from_failure_impl(failure)

    @staticmethod
    def _resolve_failed_gates_view(
        summary: dict[str, Any],
        gate_failure_summary: dict[str, Any],
        gate_failure_priority: list[dict[str, Any]],
        gate_failure_severity_priority: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        """Resolve failed-gates summary and ordering from persisted report views first."""
        return _resolve_failed_gates_view_impl(
            summary=summary,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
        )

    @staticmethod
    def _filter_failed_gates_view(
        gate_failure_summary: dict[str, Any],
        gate_failure_priority: list[dict[str, Any]],
        gate_failure_severity_priority: list[dict[str, Any]],
        only_expected_severity: str | None,
        resolved_only_pass_failure: str | None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
        """Apply gate filters to the normalized failed-gates view."""
        return _filter_failed_gates_view_impl(
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )

    @staticmethod
    def build_only_mismatches_payload(
        payload: dict[str, Any],
        summary: dict[str, Any],
        filtered_summary: dict[str, Any],
        filtered_mutations: list[dict[str, Any]],
        filtered_passes: list[str],
        mismatch_counts_by_pass: dict[str, int],
        mismatch_observables_by_pass: dict[str, list[str]],
        persisted_mismatch_priority: list[dict[str, Any]],
        mismatch_severity_rows: list[dict[str, Any]],
        mismatch_pass_context: dict[str, Any],
        requested_validation_mode: str,
        effective_validation_mode: str,
        degraded_validation: bool,
        mismatch_degraded_passes: list[dict[str, Any]],
        degraded_passes: list[dict[str, Any]],
        degradation_roles: dict[str, int],
        failed_gates: bool,
        pass_support: dict[str, Any],
        gate_evaluation: dict[str, Any],
        gate_failure_summary: dict[str, Any],
        gate_failure_priority: list[dict[str, Any]],
        gate_failure_severity_priority: list[dict[str, Any]],
        min_severity: str | None,
        only_expected_severity: str | None,
        resolved_only_pass_failure: str | None,
        validation_policy: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Build the filtered payload for --only-mismatches view."""
        return _build_only_mismatches_payload_impl(
            payload=payload,
            summary=summary,
            filtered_summary=filtered_summary,
            filtered_mutations=filtered_mutations,
            filtered_passes=filtered_passes,
            mismatch_counts_by_pass=mismatch_counts_by_pass,
            mismatch_observables_by_pass=mismatch_observables_by_pass,
            persisted_mismatch_priority=persisted_mismatch_priority,
            mismatch_severity_rows=mismatch_severity_rows,
            mismatch_pass_context=mismatch_pass_context,
            requested_validation_mode=requested_validation_mode,
            effective_validation_mode=effective_validation_mode,
            degraded_validation=degraded_validation,
            mismatch_degraded_passes=mismatch_degraded_passes,
            degraded_passes=degraded_passes,
            degradation_roles=degradation_roles,
            failed_gates=failed_gates,
            pass_support=pass_support,
            gate_evaluation=gate_evaluation,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            min_severity=min_severity,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
            validation_policy=validation_policy,
        )

    @staticmethod
    def build_report_filters(
        resolved_only_pass: str | None,
        only_status: str | None,
        only_degraded: bool,
        only_failed_gates: bool,
        only_risky_passes: bool,
        only_uncovered_passes: bool,
        only_covered_passes: bool,
        only_clean_passes: bool,
        only_structural_risk: bool,
        only_symbolic_risk: bool,
        only_mismatches: bool,
        min_severity: str | None,
        only_expected_severity: str | None,
        resolved_only_pass_failure: str | None,
    ) -> dict[str, Any]:
        """Build a report_filters dict for machine-readable consumers."""
        return _build_report_filters_impl(
            resolved_only_pass=resolved_only_pass,
            only_status=only_status,
            only_degraded=only_degraded,
            only_failed_gates=only_failed_gates,
            only_risky_passes=only_risky_passes,
            only_uncovered_passes=only_uncovered_passes,
            only_covered_passes=only_covered_passes,
            only_clean_passes=only_clean_passes,
            only_structural_risk=only_structural_risk,
            only_symbolic_risk=only_symbolic_risk,
            only_mismatches=only_mismatches,
            min_severity=min_severity,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )
