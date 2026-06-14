"""Artifact assembly helpers extracted from ReportAssembler."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from r2morph.core.report_helpers import (
    _build_discarded_mutation_priority,
    _build_pass_capability_summary_map,
    _build_pass_region_evidence_map,
    _build_pass_triage_map,
    _build_validation_role_map,
    _summarize_discarded_mutations,
    _summarize_normalized_pass_results,
    _summarize_pass_capability_rows,
    _summarize_pass_evidence_compact,
    _summarize_pass_triage_rows,
    _summarize_structural_evidence,
    _summarize_symbolic_overview,
    _summarize_validation_adjustment_rows,
    _summarize_validation_adjustments,
    _summarize_validation_role_rows,
)
from r2morph.core.support import classify_target_support
from r2morph.protocols import MutationPassProtocol, ReportViewBuilderProtocol
from r2morph.reporting.report_context import ReportViewInputs


def build_report_artifacts(
    *,
    payload: dict[str, Any],
    pass_results: dict[str, Any],
    enrichments: dict[str, Any],
    aggregate_structural_regions: list[dict[str, Any]],
    gate_failures: dict[str, Any] | None,
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    pipeline_passes: Sequence[MutationPassProtocol],
    report_view_builder: ReportViewBuilderProtocol,
) -> dict[str, Any]:
    """Compute validation, triage, and view artifacts for the report."""
    pass_validation_context = {
        pass_name: dict(pass_result.get("validation_context", {}))
        for pass_name, pass_result in pass_results.items()
        if pass_result.get("validation_context")
    }
    structural_evidence = _summarize_structural_evidence(aggregate_structural_regions)
    support_profile = classify_target_support(
        str(payload.get("format", "")),
        str(payload.get("arch", "")),
        int(payload["bits"]) if payload.get("bits") is not None else None,
    )
    pass_support = {mutation.name: mutation.get_support().to_dict() for mutation in pipeline_passes}
    pass_capabilities = {
        pass_name: support.get("validator_capabilities", {}) for pass_name, support in pass_support.items()
    }
    for pass_name in pass_results:
        pass_capabilities.setdefault(pass_name, {})
    pass_capability_summary = _summarize_pass_capability_rows(pass_capabilities)
    pass_capability_summary_map = _build_pass_capability_summary_map(pass_capability_summary)
    pass_evidence = enrichments["pass_evidence"]
    pass_evidence_map = {row.get("pass_name", "unknown"): dict(row) for row in pass_evidence if row.get("pass_name")}
    validation_role_rows = _summarize_validation_role_rows(pass_validation_context)
    validation_role_map = _build_validation_role_map(validation_role_rows)
    discarded_mutation_summary = _summarize_discarded_mutations(list(payload.get("discarded_mutations_detail", [])))
    discarded_mutation_priority = _build_discarded_mutation_priority(discarded_mutation_summary)
    pass_triage_rows = _summarize_pass_triage_rows(
        pass_results,
        pass_capability_summary_map,
    )
    pass_triage_map = _build_pass_triage_map(pass_triage_rows)
    pass_symbolic_summary = enrichments["pass_symbolic_summary"]
    symbolic_overview = _summarize_symbolic_overview(
        enrichments["symbolic_coverage_by_pass"],
        enrichments["symbolic_status_counts"],
    )
    pass_evidence_compact = _summarize_pass_evidence_compact(pass_triage_rows)
    pass_region_evidence_map = _build_pass_region_evidence_map(pass_results)
    normalized_pass_results = _summarize_normalized_pass_results(
        pass_results,
        pass_triage_map=pass_triage_map,
        pass_capability_summary_map=pass_capability_summary_map,
        validation_role_map=validation_role_map,
        pass_evidence_map=pass_evidence_map,
        pass_symbolic_summary=pass_symbolic_summary,
    )
    validation_adjustments = _summarize_validation_adjustments(
        requested_mode=payload.get(
            "requested_validation_mode",
            payload.get("validation_mode", "off"),
        ),
        effective_mode=payload.get("validation_mode", "off"),
        validation_policy=payload.get("validation_policy"),
        validation_role_rows=validation_role_rows,
    )
    validation_adjustment_rows = _summarize_validation_adjustment_rows(
        validation_role_rows,
        validation_adjustments,
        gate_failures if isinstance(gate_failures, dict) else {},
    )
    report_views = report_view_builder.build_report_views(
        ReportViewInputs(
            pass_risk_buckets=enrichments["pass_risk_buckets"],
            pass_coverage_buckets=enrichments["pass_coverage_buckets"],
            pass_triage_rows=pass_triage_rows,
            normalized_pass_results=normalized_pass_results,
            pass_symbolic_summary=pass_symbolic_summary,
            pass_evidence_map=pass_evidence_map,
            pass_region_evidence_map=pass_region_evidence_map,
            pass_validation_context=pass_validation_context,
            pass_capability_summary_map=pass_capability_summary_map,
            observable_mismatch_priority=enrichments["observable_mismatch_priority"],
            observable_mismatch_map=enrichments["observable_mismatch_map"],
            symbolic_severity_by_pass=enrichments["symbolic_severity_by_pass"],
            gate_failure_priority=gate_failure_priority,
            gate_failure_summary=gate_failures if isinstance(gate_failures, dict) else {},
            gate_failure_severity_priority=gate_failure_severity_priority,
            discarded_mutation_priority=discarded_mutation_priority,
            discarded_mutation_summary=discarded_mutation_summary,
            validation_adjustment_rows=validation_adjustment_rows,
        )
    )
    return {
        "pass_validation_context": pass_validation_context,
        "structural_evidence": structural_evidence,
        "support_profile": support_profile,
        "pass_support": pass_support,
        "pass_capabilities": pass_capabilities,
        "pass_capability_summary": pass_capability_summary,
        "pass_capability_summary_map": pass_capability_summary_map,
        "pass_evidence_map": pass_evidence_map,
        "validation_role_rows": validation_role_rows,
        "validation_role_map": validation_role_map,
        "discarded_mutation_summary": discarded_mutation_summary,
        "discarded_mutation_priority": discarded_mutation_priority,
        "pass_triage_rows": pass_triage_rows,
        "pass_triage_map": pass_triage_map,
        "symbolic_overview": symbolic_overview,
        "pass_evidence_compact": pass_evidence_compact,
        "pass_region_evidence_map": pass_region_evidence_map,
        "normalized_pass_results": normalized_pass_results,
        "validation_adjustments": validation_adjustments,
        "validation_adjustment_rows": validation_adjustment_rows,
        "report_views": report_views.to_dict(),
    }
