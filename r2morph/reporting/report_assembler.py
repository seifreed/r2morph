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
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from r2morph.core.report_helpers import (
    REPORT_SCHEMA_VERSION,
    _build_evidence_summary_for_pass,
    _build_observable_mismatch_map,
    _build_observable_mismatch_priority,
    _build_symbolic_summary_for_pass,
    _summarize_degradation_roles,
    _summarize_diff_digest,
    _summarize_observable_mismatches_by_pass,
    _summarize_pass_coverage_buckets,
    _summarize_pass_evidence,
    _summarize_pass_risk_buckets,
    _summarize_pass_timings,
    _summarize_symbolic_coverage_by_pass,
    _summarize_symbolic_issue_passes,
    _summarize_symbolic_severity_by_pass,
    _summarize_symbolic_statuses,
)
from r2morph.core.support import PRODUCT_SUPPORT
from r2morph.protocols import (
    GateFailureReporterProtocol,
    MutationPassProtocol,
    ReportViewBuilderProtocol,
)
from r2morph.reporting.report_assembler_artifacts import build_report_artifacts


@dataclass(frozen=True)
class _ReportComputation:
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
        return build_report_artifacts(
            payload=payload,
            pass_results=pass_results,
            enrichments=enrichments,
            aggregate_structural_regions=aggregate_structural_regions,
            gate_failures=gate_failures,
            gate_failure_priority=self._gate_failure_reporter.build_gate_failure_priority(gate_failures),
            gate_failure_severity_priority=self._gate_failure_reporter.build_gate_failure_severity_priority(
                gate_failures
            ),
            pipeline_passes=pipeline_passes,
            report_view_builder=self._report_view_builder,
        )

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
        aggregate_regions: list[Any] = []
        aggregate_changed_bytes = 0
        aggregate_structural_regions: list[Any] = []
        for pass_result in pass_results.values():
            diff_summary = pass_result.get("diff_summary", {})
            aggregate_regions.extend(diff_summary.get("changed_regions", []))
            aggregate_changed_bytes += int(diff_summary.get("changed_bytes", 0))
            aggregate_structural_regions.extend(diff_summary.get("structural_regions", []))
        gate_evaluation = payload.get("gate_evaluation")
        gate_failures = (
            self._gate_failure_reporter.summarize_gate_failures(gate_evaluation)
            if isinstance(gate_evaluation, dict)
            else payload.get("gate_failures")
        )
        enrichments = self._enrich_pass_results(pass_results, mutations)
        artifacts = self._compute_report_artifacts(
            payload,
            pass_results,
            enrichments,
            aggregate_structural_regions,
            gate_failures,
            pipeline_passes,
        )
        comp = _ReportComputation(
            payload=payload,
            pass_results=pass_results,
            mutations=mutations,
            aggregate_regions=aggregate_regions,
            aggregate_changed_bytes=aggregate_changed_bytes,
            aggregate_structural_regions=aggregate_structural_regions,
            degradation_role_counts=_summarize_degradation_roles(pass_results),
            pass_timing_summary=_summarize_pass_timings(pass_results),
            diff_digest=_summarize_diff_digest(pass_results),
            gate_evaluation=gate_evaluation,
            gate_failures=gate_failures,
            gate_failure_priority=self._gate_failure_reporter.build_gate_failure_priority(gate_failures),
            gate_failure_severity_priority=self._gate_failure_reporter.build_gate_failure_severity_priority(
                gate_failures
            ),
            enrichments=enrichments,
            artifacts=artifacts,
            pass_evidence_priority=[dict(row) for row in enrichments["pass_evidence"]],
        )
        return self._build_report_document(comp)

    def _build_report_document(self, comp: _ReportComputation) -> dict[str, Any]:
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
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
            "summary": self._build_summary_section(comp),
            "config": comp.payload.get("config", {}),
            "support_matrix": PRODUCT_SUPPORT.to_dict(),
            "support_profile": comp.artifacts["support_profile"],
            "validation_policy": comp.payload.get("validation_policy"),
            "metadata": self._build_report_metadata(comp.payload),
        }

    def _build_summary_section(self, comp: _ReportComputation) -> dict[str, Any]:
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
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
