"""Report assembly relocated out of core/engine.py (CLAUDE.md §6/§7).

ReportAssembler owns the machine-readable engine report. It depends only
on core.report_helpers (pure helpers), core.support, and the injected
GateFailureReporter / ReportViewBuilder protocols — never on
core.engine. MorphEngine receives a ReportAssembler through
ReportBuilderProtocol, so core/ never imports reporting/ at module
level.
"""

import platform
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from r2morph.core.report_helpers import (
    REPORT_SCHEMA_VERSION,
    _build_discarded_mutation_priority,
    _build_evidence_summary_for_pass,
    _build_observable_mismatch_map,
    _build_observable_mismatch_priority,
    _build_pass_capability_summary_map,
    _build_pass_region_evidence_map,
    _build_pass_triage_map,
    _build_symbolic_summary_for_pass,
    _build_validation_role_map,
    _summarize_degradation_roles,
    _summarize_diff_digest,
    _summarize_discarded_mutations,
    _summarize_normalized_pass_results,
    _summarize_observable_mismatches_by_pass,
    _summarize_pass_capability_rows,
    _summarize_pass_coverage_buckets,
    _summarize_pass_evidence,
    _summarize_pass_evidence_compact,
    _summarize_pass_risk_buckets,
    _summarize_pass_timings,
    _summarize_pass_triage_rows,
    _summarize_structural_evidence,
    _summarize_symbolic_coverage_by_pass,
    _summarize_symbolic_issue_passes,
    _summarize_symbolic_overview,
    _summarize_symbolic_severity_by_pass,
    _summarize_symbolic_statuses,
    _summarize_validation_adjustment_rows,
    _summarize_validation_adjustments,
    _summarize_validation_role_rows,
)
from r2morph.core.support import PRODUCT_SUPPORT, classify_target_support
from r2morph.protocols import (
    GateFailureReporterProtocol,
    MutationPassProtocol,
    ReportViewBuilderProtocol,
)


class ReportAssembler:
    """Assembles the machine-readable engine report (was core/engine.py)."""

    def __init__(
        self,
        gate_failure_reporter: GateFailureReporterProtocol,
        report_view_builder: ReportViewBuilderProtocol,
    ) -> None:
        self._gate_failure_reporter = gate_failure_reporter
        self._report_view_builder = report_view_builder

    def _enrich_pass_results(
        self,
        pass_results: dict[str, Any],
        mutations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Enrich pass results with symbolic/evidence summaries and build derived maps."""
        symbolic_issue_passes = _summarize_symbolic_issue_passes(mutations)
        symbolic_coverage_by_pass = _summarize_symbolic_coverage_by_pass(mutations)
        symbolic_status_counts, symbolic_status_rows, symbolic_status_map = _summarize_symbolic_statuses(mutations)
        observable_mismatch_by_pass = _summarize_observable_mismatches_by_pass(mutations)
        for pass_name, pass_result in pass_results.items():
            pass_result["symbolic_summary"] = _build_symbolic_summary_for_pass(
                pass_name,
                mutations,
            )
            pass_result["evidence_summary"] = _build_evidence_summary_for_pass(
                pass_name,
                pass_result,
            )
        symbolic_severity_by_pass = _summarize_symbolic_severity_by_pass(pass_results)
        return {
            "symbolic_issue_passes": symbolic_issue_passes,
            "symbolic_coverage_by_pass": symbolic_coverage_by_pass,
            "symbolic_status_counts": symbolic_status_counts,
            "symbolic_status_rows": symbolic_status_rows,
            "symbolic_status_map": symbolic_status_map,
            "observable_mismatch_by_pass": observable_mismatch_by_pass,
            "observable_mismatch_map": _build_observable_mismatch_map(observable_mismatch_by_pass),
            "observable_mismatch_priority": _build_observable_mismatch_priority(observable_mismatch_by_pass),
            "symbolic_severity_by_pass": symbolic_severity_by_pass,
            "symbolic_issue_map": {
                str(row.get("pass_name")): dict(row) for row in symbolic_issue_passes if row.get("pass_name")
            },
            "symbolic_coverage_map": {
                str(row.get("pass_name")): dict(row) for row in symbolic_coverage_by_pass if row.get("pass_name")
            },
            "symbolic_severity_map": {
                str(row.get("pass_name")): dict(row) for row in symbolic_severity_by_pass if row.get("pass_name")
            },
            "pass_evidence": _summarize_pass_evidence(pass_results),
            "pass_coverage_buckets": _summarize_pass_coverage_buckets(pass_results),
            "pass_risk_buckets": _summarize_pass_risk_buckets(pass_results),
            "pass_symbolic_summary": {
                pass_name: dict(pass_result.get("symbolic_summary", {}))
                for pass_name, pass_result in pass_results.items()
                if pass_result.get("symbolic_summary")
            },
        }

    def _compute_report_artifacts(
        self,
        payload: dict[str, Any],
        pass_results: dict[str, Any],
        enrichments: dict[str, Any],
        aggregate_structural_regions: list[dict[str, Any]],
        gate_failures: dict[str, Any] | None,
        pipeline_passes: Sequence[MutationPassProtocol],
    ) -> dict[str, Any]:
        """Compute validation/triage/view artifacts for the final report."""
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
        pass_evidence_map = {
            row.get("pass_name", "unknown"): dict(row) for row in pass_evidence if row.get("pass_name")
        }
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
        report_views = self._report_view_builder.build_report_views(
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
            gate_failure_priority=self._gate_failure_reporter.build_gate_failure_priority(gate_failures),
            gate_failure_summary=gate_failures if isinstance(gate_failures, dict) else {},
            gate_failure_severity_priority=self._gate_failure_reporter.build_gate_failure_severity_priority(
                gate_failures
            ),
            discarded_mutation_priority=discarded_mutation_priority,
            discarded_mutation_summary=discarded_mutation_summary,
            validation_adjustment_rows=validation_adjustment_rows,
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

    def assemble_report(
        self,
        result: dict[str, Any] | None,
        *,
        pipeline_passes: Sequence[MutationPassProtocol],
        last_result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Build a stable machine-readable engine report."""
        payload = result or last_result or {}
        pass_results = {
            pass_name: dict(pass_result) for pass_name, pass_result in payload.get("pass_results", {}).items()
        }
        mutations = payload.get("mutations", [])
        aggregate_regions = []
        aggregate_changed_bytes = 0
        aggregate_structural_regions = []
        for pass_result in pass_results.values():
            diff_summary = pass_result.get("diff_summary", {})
            aggregate_regions.extend(diff_summary.get("changed_regions", []))
            aggregate_changed_bytes += int(diff_summary.get("changed_bytes", 0))
            aggregate_structural_regions.extend(diff_summary.get("structural_regions", []))
        degradation_role_counts = _summarize_degradation_roles(pass_results)
        pass_timing_summary = _summarize_pass_timings(pass_results)
        diff_digest = _summarize_diff_digest(pass_results)
        gate_evaluation = payload.get("gate_evaluation")
        gate_failures = (
            self._gate_failure_reporter.summarize_gate_failures(gate_evaluation)
            if isinstance(gate_evaluation, dict)
            else payload.get("gate_failures")
        )
        gate_failure_priority = self._gate_failure_reporter.build_gate_failure_priority(gate_failures)
        gate_failure_severity_priority = self._gate_failure_reporter.build_gate_failure_severity_priority(gate_failures)
        enrichments = self._enrich_pass_results(pass_results, mutations)
        artifacts = self._compute_report_artifacts(
            payload,
            pass_results,
            enrichments,
            aggregate_structural_regions,
            gate_failures,
            pipeline_passes,
        )
        pass_evidence_priority = [dict(row) for row in enrichments["pass_evidence"]]
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "input": {
                "path": payload.get("input_path"),
                "arch": payload.get("arch"),
                "bits": payload.get("bits"),
                "format": payload.get("format"),
                "functions": payload.get("functions"),
            },
            "output": {
                "working_path": payload.get("working_path"),
            },
            "passes": pass_results,
            "pass_support": artifacts["pass_support"],
            "pass_capabilities": artifacts["pass_capabilities"],
            "pass_capability_summary": artifacts["pass_capability_summary"],
            "pass_capability_summary_map": artifacts["pass_capability_summary_map"],
            "mutations": mutations,
            "discarded_mutations": payload.get("discarded_mutations_detail", []),
            "discarded_mutation_summary": artifacts["discarded_mutation_summary"],
            "discarded_mutation_priority": artifacts["discarded_mutation_priority"],
            "gate_evaluation": gate_evaluation,
            "gate_failures": gate_failures,
            "gate_failure_priority": gate_failure_priority,
            "gate_failure_severity_priority": gate_failure_severity_priority,
            "validation": payload.get("validation", {}),
            "symbolic_issue_map": enrichments["symbolic_issue_map"],
            "symbolic_coverage_map": enrichments["symbolic_coverage_map"],
            "symbolic_severity_map": enrichments["symbolic_severity_map"],
            "symbolic_status_counts": enrichments["symbolic_status_counts"],
            "symbolic_status_rows": enrichments["symbolic_status_rows"],
            "symbolic_status_map": enrichments["symbolic_status_map"],
            "symbolic_overview": artifacts["symbolic_overview"],
            "observable_mismatch_by_pass": enrichments["observable_mismatch_by_pass"],
            "observable_mismatch_map": enrichments["observable_mismatch_map"],
            "observable_mismatch_priority": enrichments["observable_mismatch_priority"],
            "timings": {
                "execution_time_seconds": payload.get("execution_time_seconds", 0.0),
                "passes": pass_timing_summary,
            },
            "diff_digest": diff_digest,
            "pass_evidence": enrichments["pass_evidence"],
            "pass_evidence_priority": pass_evidence_priority,
            "pass_coverage_buckets": enrichments["pass_coverage_buckets"],
            "pass_risk_buckets": enrichments["pass_risk_buckets"],
            "pass_symbolic_summary": enrichments["pass_symbolic_summary"],
            "pass_validation_context": artifacts["pass_validation_context"],
            "validation_role_rows": artifacts["validation_role_rows"],
            "validation_role_map": artifacts["validation_role_map"],
            "pass_evidence_map": artifacts["pass_evidence_map"],
            "pass_region_evidence_map": artifacts["pass_region_evidence_map"],
            "pass_triage_rows": artifacts["pass_triage_rows"],
            "pass_triage_map": artifacts["pass_triage_map"],
            "pass_evidence_compact": artifacts["pass_evidence_compact"],
            "normalized_pass_results": artifacts["normalized_pass_results"],
            "report_views": artifacts["report_views"],
            "structural_evidence": artifacts["structural_evidence"],
            "validation_adjustments": artifacts["validation_adjustments"],
            "validation_adjustment_rows": artifacts["validation_adjustment_rows"],
            "summary": {
                "schema_version": REPORT_SCHEMA_VERSION,
                "passes_run": payload.get("passes_run", 0),
                "total_mutations": payload.get("total_mutations", 0),
                "rolled_back_passes": payload.get("rolled_back_passes", 0),
                "failed_passes": payload.get("failed_passes", 0),
                "discarded_mutations": payload.get("discarded_mutations", 0),
                "discarded_mutation_summary": artifacts["discarded_mutation_summary"],
                "discarded_mutation_priority": artifacts["discarded_mutation_priority"],
                "changed_bytes": aggregate_changed_bytes,
                "changed_regions": aggregate_regions,
                "structural_regions": aggregate_structural_regions,
                "structural_evidence": artifacts["structural_evidence"],
                "requested_validation_mode": payload.get(
                    "requested_validation_mode",
                    payload.get("validation_mode", "off"),
                ),
                "validation_mode": payload.get("validation_mode", "off"),
                "gate_evaluation": (
                    gate_evaluation.get("results", {})
                    if isinstance(gate_evaluation, dict)
                    else payload.get("summary", {}).get("gate_evaluation")
                ),
                "gate_failures": gate_failures,
                "gate_failure_priority": gate_failure_priority,
                "gate_failure_severity_priority": gate_failure_severity_priority,
                "degradation_roles": degradation_role_counts,
                "symbolic_issue_passes": enrichments["symbolic_issue_passes"],
                "symbolic_coverage_by_pass": enrichments["symbolic_coverage_by_pass"],
                "symbolic_severity_by_pass": enrichments["symbolic_severity_by_pass"],
                "symbolic_issue_map": enrichments["symbolic_issue_map"],
                "symbolic_coverage_map": enrichments["symbolic_coverage_map"],
                "symbolic_severity_map": enrichments["symbolic_severity_map"],
                "symbolic_status_counts": enrichments["symbolic_status_counts"],
                "symbolic_status_rows": enrichments["symbolic_status_rows"],
                "symbolic_status_map": enrichments["symbolic_status_map"],
                "symbolic_overview": artifacts["symbolic_overview"],
                "observable_mismatch_by_pass": enrichments["observable_mismatch_by_pass"],
                "observable_mismatch_map": enrichments["observable_mismatch_map"],
                "observable_mismatch_priority": enrichments["observable_mismatch_priority"],
                "pass_evidence": enrichments["pass_evidence"],
                "pass_evidence_priority": pass_evidence_priority,
                "pass_coverage_buckets": enrichments["pass_coverage_buckets"],
                "pass_risk_buckets": enrichments["pass_risk_buckets"],
                "pass_symbolic_summary": enrichments["pass_symbolic_summary"],
                "pass_validation_context": artifacts["pass_validation_context"],
                "validation_role_rows": artifacts["validation_role_rows"],
                "validation_role_map": artifacts["validation_role_map"],
                "pass_capabilities": artifacts["pass_capabilities"],
                "pass_capability_summary": artifacts["pass_capability_summary"],
                "pass_capability_summary_map": artifacts["pass_capability_summary_map"],
                "pass_evidence_map": artifacts["pass_evidence_map"],
                "pass_region_evidence_map": artifacts["pass_region_evidence_map"],
                "pass_triage_rows": artifacts["pass_triage_rows"],
                "pass_triage_map": artifacts["pass_triage_map"],
                "pass_evidence_compact": artifacts["pass_evidence_compact"],
                "normalized_pass_results": artifacts["normalized_pass_results"],
                "report_views": artifacts["report_views"],
                "pass_timing_summary": pass_timing_summary,
                "diff_digest": diff_digest,
                "support_profile": artifacts["support_profile"],
                "validation_adjustments": artifacts["validation_adjustments"],
                "validation_adjustment_rows": artifacts["validation_adjustment_rows"],
                "execution_time_seconds": payload.get("execution_time_seconds", 0.0),
            },
            "config": payload.get("config", {}),
            "support_matrix": PRODUCT_SUPPORT.to_dict(),
            "support_profile": artifacts["support_profile"],
            "validation_policy": payload.get("validation_policy"),
            "metadata": self._build_report_metadata(payload),
        }

    @staticmethod
    def _build_report_metadata(payload: dict[str, Any]) -> dict[str, Any]:
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
