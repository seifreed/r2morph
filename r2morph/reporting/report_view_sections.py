"""Section builders for report view assembly."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_context import ReportViews
from r2morph.reporting.report_view_details import _assemble_report_views
from r2morph.reporting.report_view_gate_views import build_gate_views
from r2morph.reporting.report_view_mismatch_views import build_mismatch_views
from r2morph.reporting.report_view_pass_views import build_pass_views
from r2morph.reporting.report_view_projections import _build_lookup_maps
from r2morph.reporting.report_view_summary_payload import build_summary_payload


def build_report_views(
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
    """Persist small precomputed views for common report filters."""
    lookups = _build_lookup_maps(
        normalized_pass_results=normalized_pass_results,
        pass_triage_rows=pass_triage_rows,
        symbolic_severity_by_pass=symbolic_severity_by_pass,
        discarded_mutation_summary=discarded_mutation_summary,
    )
    normalized_pass_map = lookups["normalized_pass_map"]
    triage_priority = lookups["triage_priority"]
    symbolic_severity_map = lookups["symbolic_severity_map"]
    discarded_by_pass = lookups["discarded_by_pass"]

    gates = build_gate_views(
        gate_failure_priority=gate_failure_priority,
        gate_failure_summary=gate_failure_summary,
        gate_failure_severity_priority=gate_failure_severity_priority,
        normalized_pass_map=normalized_pass_map,
    )
    failed_gates_rows = gates["failed_gates_rows"]
    failed_gates_by_pass = gates["failed_gates_by_pass"]
    failed_gates_expected_severity = gates["failed_gates_expected_severity"]

    passes = build_pass_views(
        normalized_pass_results=normalized_pass_results,
        pass_region_evidence_map=pass_region_evidence_map,
        pass_validation_context=pass_validation_context,
        pass_symbolic_summary=pass_symbolic_summary,
        pass_evidence_map=pass_evidence_map,
        pass_capability_summary_map=pass_capability_summary_map,
        normalized_pass_map=normalized_pass_map,
        triage_priority=triage_priority,
        discarded_by_pass=discarded_by_pass,
        failed_gates_by_pass=failed_gates_by_pass,
    )
    general_pass_rows = passes["general_pass_rows"]
    only_pass = passes["only_pass"]

    mismatches = build_mismatch_views(
        observable_mismatch_priority=observable_mismatch_priority,
        normalized_pass_map=normalized_pass_map,
        symbolic_severity_map=symbolic_severity_map,
        pass_validation_context=pass_validation_context,
        pass_region_evidence_map=pass_region_evidence_map,
    )
    mismatch_rows = mismatches["mismatch_rows"]
    mismatch_by_pass = mismatches["mismatch_by_pass"]

    filter_buckets = {
        "risky": list(pass_risk_buckets.get("risky", [])),
        "structural_risk": list(pass_risk_buckets.get("structural", [])),
        "symbolic_risk": list(pass_risk_buckets.get("symbolic", [])),
        "clean": list(pass_risk_buckets.get("clean", [])),
        "covered": list(pass_coverage_buckets.get("covered", [])),
        "uncovered": list(pass_coverage_buckets.get("uncovered", [])),
    }

    summary = build_summary_payload(
        normalized_pass_results=normalized_pass_results,
        symbolic_severity_by_pass=symbolic_severity_by_pass,
        gate_failure_priority=gate_failure_priority,
        gate_failure_summary=gate_failure_summary,
        gate_failure_severity_priority=gate_failure_severity_priority,
        discarded_mutation_priority=discarded_mutation_priority,
        discarded_mutation_summary=discarded_mutation_summary,
        validation_adjustment_rows=validation_adjustment_rows,
        pass_risk_buckets=pass_risk_buckets,
        pass_coverage_buckets=pass_coverage_buckets,
        triage_priority=triage_priority,
        general_pass_rows=general_pass_rows,
        failed_gates_rows=failed_gates_rows,
        failed_gates_expected_severity=failed_gates_expected_severity,
        filter_buckets=filter_buckets,
    )
    degraded_rows = summary["degraded_rows"]
    general_symbolic = summary["general_symbolic"]
    general_gates = summary["general_gates"]
    general_degradation = summary["general_degradation"]
    general_discards = summary["general_discards"]
    general_summary_payload = summary["general_summary_payload"]
    general_summary_rows = summary["general_summary_rows"]
    general_renderer_state = summary["general_renderer_state"]

    return _assemble_report_views(
        general_pass_rows=general_pass_rows,
        general_summary_payload=general_summary_payload,
        general_summary_rows=general_summary_rows,
        general_renderer_state=general_renderer_state,
        triage_priority=triage_priority,
        filter_buckets=filter_buckets,
        general_symbolic=general_symbolic,
        general_gates=general_gates,
        general_degradation=general_degradation,
        general_discards=general_discards,
        only_pass=only_pass,
        observable_mismatch_priority=observable_mismatch_priority,
        observable_mismatch_map=observable_mismatch_map,
        mismatch_rows=mismatch_rows,
        mismatch_by_pass=mismatch_by_pass,
        gate_failure_priority=gate_failure_priority,
        gate_failure_summary=gate_failure_summary,
        gate_failure_severity_priority=gate_failure_severity_priority,
        failed_gates_rows=failed_gates_rows,
        failed_gates_by_pass=failed_gates_by_pass,
        failed_gates_expected_severity=failed_gates_expected_severity,
        degraded_rows=degraded_rows,
        discarded_mutation_priority=discarded_mutation_priority,
        discarded_mutation_summary=discarded_mutation_summary,
    )
