"""Report assembly relocated out of core/engine.py (CLAUDE.md §6/§7).

ReportAssembler owns the machine-readable engine report. It depends only
on core.report_helpers (pure helpers), core.support, and the injected
GateFailureReporter / ReportViewBuilder protocols — never on
core.engine. MorphEngine receives a ReportAssembler through
ReportBuilderProtocol, so core/ never imports reporting/ at module
level.
"""

from collections.abc import Sequence
from typing import Any

from r2morph.core.report_helpers import (
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
from r2morph.protocols import (
    GateFailureReporterProtocol,
    MutationPassProtocol,
    ReportViewBuilderProtocol,
)
from r2morph.reporting.report_assembler_document import (
    ReportComputation,
    build_report_document,
    compute_report_artifacts,
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
        return compute_report_artifacts(
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
        comp = ReportComputation(
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
        return build_report_document(comp)
