"""Report view builder extracted from engine.py."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import ReportViews
from r2morph.reporting.report_view_sections import build_report_views


class ReportViewBuilder:
    """Service adapter over the module-level build_report_views helper."""

    def build_report_views(
        self,
        *,
        pass_risk_buckets: dict[str, list[str]],
        pass_coverage_buckets: dict[str, list[str]],
        pass_triage_rows: list[dict[str, Any]],
        normalized_pass_results: list[dict[str, Any]],
        pass_symbolic_summary: dict[str, Any],
        pass_evidence_map: dict[str, Any],
        pass_region_evidence_map: dict[str, list[dict[str, Any]]],
        pass_validation_context: dict[str, Any],
        pass_capability_summary_map: dict[str, Any],
        observable_mismatch_priority: list[dict[str, Any]],
        observable_mismatch_map: dict[str, dict[str, Any]],
        symbolic_severity_by_pass: list[dict[str, Any]],
        gate_failure_priority: list[dict[str, Any]],
        gate_failure_summary: dict[str, Any] | None,
        gate_failure_severity_priority: list[dict[str, Any]],
        discarded_mutation_priority: list[dict[str, Any]],
        discarded_mutation_summary: dict[str, Any],
        validation_adjustment_rows: list[dict[str, Any]],
    ) -> ReportViews:
        return build_report_views(
            pass_risk_buckets=pass_risk_buckets,
            pass_coverage_buckets=pass_coverage_buckets,
            pass_triage_rows=pass_triage_rows,
            normalized_pass_results=normalized_pass_results,
            pass_symbolic_summary=pass_symbolic_summary,
            pass_evidence_map=pass_evidence_map,
            pass_region_evidence_map=pass_region_evidence_map,
            pass_validation_context=pass_validation_context,
            pass_capability_summary_map=pass_capability_summary_map,
            observable_mismatch_priority=observable_mismatch_priority,
            observable_mismatch_map=observable_mismatch_map,
            symbolic_severity_by_pass=symbolic_severity_by_pass,
            gate_failure_priority=gate_failure_priority,
            gate_failure_summary=gate_failure_summary,
            gate_failure_severity_priority=gate_failure_severity_priority,
            discarded_mutation_priority=discarded_mutation_priority,
            discarded_mutation_summary=discarded_mutation_summary,
            validation_adjustment_rows=validation_adjustment_rows,
        )
