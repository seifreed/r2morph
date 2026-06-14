"""Report document assembly helpers extracted from report_assembler."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from r2morph.core.support import PRODUCT_SUPPORT
from r2morph.reporting.report_assembler_artifacts import build_report_artifacts


@dataclass(frozen=True)
class ReportComputation:
    """Immutable bundle of the intermediates the report document needs."""

    payload: dict[str, Any]
    pass_results: dict[str, Any]
    mutations: Any
    aggregate_regions: list[Any]
    aggregate_changed_bytes: int
    aggregate_structural_regions: list[Any]
    degradation_role_counts: dict[str, int]
    pass_timing_summary: list[dict[str, Any]]
    diff_digest: dict[str, Any]
    gate_evaluation: Any
    gate_failures: dict[str, Any] | None
    gate_failure_priority: list[dict[str, Any]]
    gate_failure_severity_priority: list[dict[str, Any]]
    enrichments: dict[str, Any]
    artifacts: dict[str, Any]
    pass_evidence_priority: list[dict[str, Any]]


def compute_report_artifacts(
    *,
    payload: dict[str, Any],
    pass_results: dict[str, Any],
    enrichments: dict[str, Any],
    aggregate_structural_regions: list[dict[str, Any]],
    gate_failures: dict[str, Any] | None,
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    pipeline_passes: list[Any],
    report_view_builder: Any,
) -> dict[str, Any]:
    """Compute validation, triage, and view artifacts for the report."""
    return build_report_artifacts(
        payload=payload,
        pass_results=pass_results,
        enrichments=enrichments,
        aggregate_structural_regions=aggregate_structural_regions,
        gate_failures=gate_failures,
        gate_failure_priority=gate_failure_priority,
        gate_failure_severity_priority=gate_failure_severity_priority,
        pipeline_passes=pipeline_passes,
        report_view_builder=report_view_builder,
    )


def build_report_document(comp: ReportComputation) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "input": {
            "path": comp.payload.get("input_path"),
            "arch": comp.payload.get("arch"),
            "bits": comp.payload.get("bits"),
            "format": comp.payload.get("format"),
            "functions": comp.payload.get("functions"),
        },
        "output": {
            "working_path": comp.payload.get("working_path"),
        },
        "passes": comp.pass_results,
        "pass_support": comp.artifacts["pass_support"],
        "pass_capabilities": comp.artifacts["pass_capabilities"],
        "pass_capability_summary": comp.artifacts["pass_capability_summary"],
        "pass_capability_summary_map": comp.artifacts["pass_capability_summary_map"],
        "mutations": comp.mutations,
        "discarded_mutations": comp.payload.get("discarded_mutations_detail", []),
        "discarded_mutation_summary": comp.artifacts["discarded_mutation_summary"],
        "discarded_mutation_priority": comp.artifacts["discarded_mutation_priority"],
        "gate_evaluation": comp.gate_evaluation,
        "gate_failures": comp.gate_failures,
        "gate_failure_priority": comp.gate_failure_priority,
        "gate_failure_severity_priority": comp.gate_failure_severity_priority,
        "validation": comp.payload.get("validation", {}),
        "symbolic_issue_map": comp.enrichments["symbolic_issue_map"],
        "symbolic_coverage_map": comp.enrichments["symbolic_coverage_map"],
        "symbolic_severity_map": comp.enrichments["symbolic_severity_map"],
        "symbolic_status_counts": comp.enrichments["symbolic_status_counts"],
        "symbolic_status_rows": comp.enrichments["symbolic_status_rows"],
        "symbolic_status_map": comp.enrichments["symbolic_status_map"],
        "symbolic_overview": comp.artifacts["symbolic_overview"],
        "observable_mismatch_by_pass": comp.enrichments["observable_mismatch_by_pass"],
        "observable_mismatch_map": comp.enrichments["observable_mismatch_map"],
        "observable_mismatch_priority": comp.enrichments["observable_mismatch_priority"],
        "timings": {
            "execution_time_seconds": comp.payload.get("execution_time_seconds", 0.0),
            "passes": comp.pass_timing_summary,
        },
        "diff_digest": comp.diff_digest,
        "pass_evidence": comp.enrichments["pass_evidence"],
        "pass_evidence_priority": comp.pass_evidence_priority,
        "pass_coverage_buckets": comp.enrichments["pass_coverage_buckets"],
        "pass_risk_buckets": comp.enrichments["pass_risk_buckets"],
        "pass_symbolic_summary": comp.enrichments["pass_symbolic_summary"],
        "pass_validation_context": comp.artifacts["pass_validation_context"],
        "validation_role_rows": comp.artifacts["validation_role_rows"],
        "validation_role_map": comp.artifacts["validation_role_map"],
        "pass_evidence_map": comp.artifacts["pass_evidence_map"],
        "pass_region_evidence_map": comp.artifacts["pass_region_evidence_map"],
        "pass_triage_rows": comp.artifacts["pass_triage_rows"],
        "pass_triage_map": comp.artifacts["pass_triage_map"],
        "pass_evidence_compact": comp.artifacts["pass_evidence_compact"],
        "normalized_pass_results": comp.artifacts["normalized_pass_results"],
        "report_views": comp.artifacts["report_views"],
        "structural_evidence": comp.artifacts["structural_evidence"],
        "validation_adjustments": comp.artifacts["validation_adjustments"],
        "validation_adjustment_rows": comp.artifacts["validation_adjustment_rows"],
        "summary": build_summary_section(comp),
        "config": comp.payload.get("config", {}),
        "support_matrix": PRODUCT_SUPPORT.to_dict(),
        "support_profile": comp.artifacts["support_profile"],
        "validation_policy": comp.payload.get("validation_policy"),
        "metadata": build_report_metadata(comp.payload),
    }


def build_summary_section(comp: ReportComputation) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "passes_run": comp.payload.get("passes_run", 0),
        "total_mutations": comp.payload.get("total_mutations", 0),
        "rolled_back_passes": comp.payload.get("rolled_back_passes", 0),
        "failed_passes": comp.payload.get("failed_passes", 0),
        "discarded_mutations": comp.payload.get("discarded_mutations", 0),
        "discarded_mutation_summary": comp.artifacts["discarded_mutation_summary"],
        "discarded_mutation_priority": comp.artifacts["discarded_mutation_priority"],
        "changed_bytes": comp.aggregate_changed_bytes,
        "changed_regions": comp.aggregate_regions,
        "structural_regions": comp.aggregate_structural_regions,
        "structural_evidence": comp.artifacts["structural_evidence"],
        "requested_validation_mode": comp.payload.get(
            "requested_validation_mode",
            comp.payload.get("validation_mode", "off"),
        ),
        "validation_mode": comp.payload.get("validation_mode", "off"),
        "gate_evaluation": (
            comp.gate_evaluation.get("results", {})
            if isinstance(comp.gate_evaluation, dict)
            else comp.payload.get("summary", {}).get("gate_evaluation")
        ),
        "gate_failures": comp.gate_failures,
        "gate_failure_priority": comp.gate_failure_priority,
        "gate_failure_severity_priority": comp.gate_failure_severity_priority,
        "degradation_roles": comp.degradation_role_counts,
        "symbolic_issue_passes": comp.enrichments["symbolic_issue_passes"],
        "symbolic_coverage_by_pass": comp.enrichments["symbolic_coverage_by_pass"],
        "symbolic_severity_by_pass": comp.enrichments["symbolic_severity_by_pass"],
        "symbolic_issue_map": comp.enrichments["symbolic_issue_map"],
        "symbolic_coverage_map": comp.enrichments["symbolic_coverage_map"],
        "symbolic_severity_map": comp.enrichments["symbolic_severity_map"],
        "symbolic_status_counts": comp.enrichments["symbolic_status_counts"],
        "symbolic_status_rows": comp.enrichments["symbolic_status_rows"],
        "symbolic_status_map": comp.enrichments["symbolic_status_map"],
        "symbolic_overview": comp.artifacts["symbolic_overview"],
        "observable_mismatch_by_pass": comp.enrichments["observable_mismatch_by_pass"],
        "observable_mismatch_map": comp.enrichments["observable_mismatch_map"],
        "observable_mismatch_priority": comp.enrichments["observable_mismatch_priority"],
        "pass_evidence": comp.enrichments["pass_evidence"],
        "pass_evidence_priority": comp.pass_evidence_priority,
        "pass_coverage_buckets": comp.enrichments["pass_coverage_buckets"],
        "pass_risk_buckets": comp.enrichments["pass_risk_buckets"],
        "pass_symbolic_summary": comp.enrichments["pass_symbolic_summary"],
        "pass_validation_context": comp.artifacts["pass_validation_context"],
        "validation_role_rows": comp.artifacts["validation_role_rows"],
        "validation_role_map": comp.artifacts["validation_role_map"],
        "pass_capabilities": comp.artifacts["pass_capabilities"],
        "pass_capability_summary": comp.artifacts["pass_capability_summary"],
        "pass_capability_summary_map": comp.artifacts["pass_capability_summary_map"],
        "pass_evidence_map": comp.artifacts["pass_evidence_map"],
        "pass_region_evidence_map": comp.artifacts["pass_region_evidence_map"],
        "pass_triage_rows": comp.artifacts["pass_triage_rows"],
        "pass_triage_map": comp.artifacts["pass_triage_map"],
        "pass_evidence_compact": comp.artifacts["pass_evidence_compact"],
        "normalized_pass_results": comp.artifacts["normalized_pass_results"],
        "report_views": comp.artifacts["report_views"],
        "pass_timing_summary": comp.pass_timing_summary,
        "diff_digest": comp.diff_digest,
        "support_profile": comp.artifacts["support_profile"],
        "validation_adjustments": comp.artifacts["validation_adjustments"],
        "validation_adjustment_rows": comp.artifacts["validation_adjustment_rows"],
        "execution_time_seconds": comp.payload.get("execution_time_seconds", 0.0),
    }


def build_report_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    import sys

    from r2morph import __version__

    return {
        "tool": "r2morph",
        "version": __version__,
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": payload.get("execution_time_seconds", 0.0),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
    }
