"""Section builders for report view assembly."""

from __future__ import annotations

from r2morph.reporting.report_context import ReportViewInputs, ReportViews
from r2morph.reporting.report_view_details import _assemble_report_views
from r2morph.reporting.report_view_gate_views import build_gate_views
from r2morph.reporting.report_view_mismatch_views import build_mismatch_views
from r2morph.reporting.report_view_pass_views import build_pass_views
from r2morph.reporting.report_view_projections import _build_lookup_maps
from r2morph.reporting.report_view_summary_payload import build_summary_payload


def build_report_views(inputs: ReportViewInputs) -> ReportViews:
    """Persist small precomputed views for common report filters."""
    pass_risk_buckets = inputs.pass_risk_buckets
    pass_coverage_buckets = inputs.pass_coverage_buckets
    pass_triage_rows = inputs.pass_triage_rows
    normalized_pass_results = inputs.normalized_pass_results
    pass_region_evidence_map = inputs.pass_region_evidence_map
    pass_validation_context = inputs.pass_validation_context
    observable_mismatch_priority = inputs.observable_mismatch_priority
    symbolic_severity_by_pass = inputs.symbolic_severity_by_pass
    gate_failure_priority = inputs.gate_failure_priority
    gate_failure_summary = inputs.gate_failure_summary
    gate_failure_severity_priority = inputs.gate_failure_severity_priority
    discarded_mutation_summary = inputs.discarded_mutation_summary

    lookups = _build_lookup_maps(
        normalized_pass_results=normalized_pass_results,
        pass_triage_rows=pass_triage_rows,
        symbolic_severity_by_pass=symbolic_severity_by_pass,
        discarded_mutation_summary=discarded_mutation_summary,
    )
    normalized_pass_map = lookups["normalized_pass_map"]
    triage_priority = lookups["triage_priority"]
    symbolic_severity_map = lookups["symbolic_severity_map"]

    gates = build_gate_views(
        gate_failure_priority=gate_failure_priority,
        gate_failure_summary=gate_failure_summary,
        gate_failure_severity_priority=gate_failure_severity_priority,
        normalized_pass_map=normalized_pass_map,
    )
    passes = build_pass_views(
        inputs,
        lookups,
        gates,
    )
    general_pass_rows = passes["general_pass_rows"]

    mismatches = build_mismatch_views(
        observable_mismatch_priority=observable_mismatch_priority,
        normalized_pass_map=normalized_pass_map,
        symbolic_severity_map=symbolic_severity_map,
        pass_validation_context=pass_validation_context,
        pass_region_evidence_map=pass_region_evidence_map,
    )
    filter_buckets = {
        "risky": list(pass_risk_buckets.get("risky", [])),
        "structural_risk": list(pass_risk_buckets.get("structural", [])),
        "symbolic_risk": list(pass_risk_buckets.get("symbolic", [])),
        "clean": list(pass_risk_buckets.get("clean", [])),
        "covered": list(pass_coverage_buckets.get("covered", [])),
        "uncovered": list(pass_coverage_buckets.get("uncovered", [])),
    }

    summary = build_summary_payload(
        inputs,
        triage_priority,
        general_pass_rows,
        gates,
        filter_buckets,
    )
    sections = {
        **lookups,
        **gates,
        **passes,
        **mismatches,
        **summary,
        "filter_buckets": filter_buckets,
    }
    return _assemble_report_views(inputs, sections)
