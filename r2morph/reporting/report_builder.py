"""
Report builder logic extracted from cli.py and engine.py.

This module handles building report payloads, context resolution,
and filtered report generation.
"""

from dataclasses import dataclass
from typing import Any

from r2morph.reporting.gate_evaluator import GateEvaluator, SEVERITY_ORDER


@dataclass
class ReportContext:
    """Resolved report context from payload and filters."""

    summary: dict[str, Any]
    resolved_only_pass: str | None
    resolved_only_pass_failure: str | None
    requested_validation_mode: str | None
    effective_validation_mode: str | None
    validation_policy: dict[str, Any] | None
    gate_evaluation: dict[str, Any]
    gate_requested: dict[str, Any]
    gate_results: dict[str, Any]
    gate_failure_summary: dict[str, Any]
    gate_failure_priority: list[dict[str, Any]]
    gate_failure_severity_priority: list[dict[str, Any]]
    failed_gates: bool
    degraded_validation: bool
    degraded_passes: list[dict[str, Any]]
    degradation_roles: dict[str, int]


@dataclass
class FilteredReport:
    """Filtered report payload with context."""

    payload: dict[str, Any]
    filtered_mutations: list[dict[str, Any]]
    filtered_summary: dict[str, Any]
    gate_evaluation: dict[str, Any]
    gate_failures: dict[str, Any]
    gate_failure_priority: list[dict[str, Any]]
    gate_failure_severity_priority: list[dict[str, Any]]
    report_filters: dict[str, Any]


class ReportBuilder:
    """Builds report payloads and resolves report contexts."""

    @staticmethod
    def resolve_report_pass_filter(pass_filter: str | None, alias_map: dict[str, str] | None = None) -> str | None:
        """Resolve a pass filter alias to canonical pass name."""
        if pass_filter is None:
            return None
        aliases = dict(alias_map or {})
        return aliases.get(pass_filter, pass_filter)

    @staticmethod
    def resolve_min_severity(min_severity: str | None) -> tuple[str | None, int | None]:
        """Validate and normalize a minimum severity option."""
        severity_order = SEVERITY_ORDER
        if min_severity is None:
            return None, None
        if min_severity not in severity_order:
            return None, None
        return min_severity, severity_order[min_severity]

    @staticmethod
    def resolve_report_context(
        payload: dict[str, Any],
        only_pass: str | None,
        only_pass_failure: str | None,
        only_expected_severity: str | None,
    ) -> ReportContext:
        """Resolve the initial report context from payload and filters."""
        summary = payload.get("summary") or {}
        resolved_only_pass = ReportBuilder.resolve_report_pass_filter(only_pass)
        resolved_only_pass_failure = ReportBuilder.resolve_report_pass_filter(only_pass_failure)
        requested_validation_mode = summary.get(
            "requested_validation_mode",
            payload.get("requested_validation_mode", payload.get("validation_mode", "off")),
        )
        effective_validation_mode = summary.get(
            "validation_mode",
            payload.get("validation_mode", "off"),
        )
        validation_policy = payload.get("validation_policy")
        gate_evaluation = payload.get("gate_evaluation") or {}
        gate_requested = dict(gate_evaluation.get("requested", {}))
        gate_results = dict(gate_evaluation.get("results", {}))

        (
            gate_failure_summary,
            gate_failure_priority,
            gate_failure_severity_priority,
            filtered_gate_failed,
        ) = ReportBuilder._resolve_report_gate_state(
            summary=summary,
            payload=payload,
            gate_evaluation=gate_evaluation,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )

        failed_gates = bool(gate_results) and not bool(gate_results.get("all_passed", True))
        if (only_expected_severity or resolved_only_pass_failure) and not gate_failure_summary.get(
            "require_pass_severity_failure_count", 0
        ):
            failed_gates = False
        if only_expected_severity or resolved_only_pass_failure:
            failed_gates = filtered_gate_failed

        degraded_validation = requested_validation_mode != effective_validation_mode
        degraded_passes = list((validation_policy or {}).get("limited_passes", []))
        degradation_roles = dict(summary.get("degradation_roles", {}))

        return ReportContext(
            summary=summary,
            resolved_only_pass=resolved_only_pass,
            resolved_only_pass_failure=resolved_only_pass_failure,
            requested_validation_mode=requested_validation_mode,
            effective_validation_mode=effective_validation_mode,
            validation_policy=validation_policy,
            gate_evaluation=gate_evaluation,
            gate_requested=gate_requested,
            gate_results=gate_results,
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            failed_gates=failed_gates,
            degraded_validation=degraded_validation,
            degraded_passes=degraded_passes,
            degradation_roles=degradation_roles,
        )

    @staticmethod
    def _resolve_report_gate_state(
        summary: dict[str, Any],
        payload: dict[str, Any],
        gate_evaluation: dict[str, Any],
        only_expected_severity: str | None,
        resolved_only_pass_failure: str | None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
        """Resolve persisted gate summaries and filtered gate state for report()."""
        gate_failure_summary = GateEvaluator.summarize_gate_failures(gate_evaluation) if gate_evaluation else {}
        gate_failure_priority = list(summary.get("gate_failure_priority", payload.get("gate_failure_priority", [])))
        gate_failure_severity_priority = list(
            summary.get(
                "gate_failure_severity_priority",
                payload.get("gate_failure_severity_priority", []),
            )
        )

        gate_failure_summary, gate_failure_priority, gate_failure_severity_priority = (
            ReportBuilder._resolve_failed_gates_view(
                summary=summary,
                gate_failure_summary=gate_failure_summary,
                gate_failure_priority=gate_failure_priority,
                gate_failure_severity_priority=gate_failure_severity_priority,
            )
        )

        if gate_failure_summary.get("require_pass_severity_failures_by_pass"):

            ordered_failures = sorted(
                gate_failure_summary["require_pass_severity_failures_by_pass"].items(),
                key=lambda item: (
                    min(ReportBuilder._expected_severity_rank_from_failure(failure) for failure in item[1]),
                    -len(item[1]),
                    item[0],
                ),
            )
            gate_failure_summary["require_pass_severity_failures_by_pass"] = {
                pass_name: failures for pass_name, failures in ordered_failures
            }

        if not gate_failure_priority:
            gate_failure_priority = GateEvaluator.build_gate_failure_priority(gate_failure_summary)

        (
            gate_failure_summary,
            gate_failure_priority,
            gate_failure_severity_priority,
            filtered_gate_failed,
        ) = ReportBuilder._filter_failed_gates_view(
            gate_failure_summary=gate_failure_summary,
            gate_failure_priority=gate_failure_priority,
            gate_failure_severity_priority=gate_failure_severity_priority,
            only_expected_severity=only_expected_severity,
            resolved_only_pass_failure=resolved_only_pass_failure,
        )

        return (
            gate_failure_summary,
            gate_failure_priority,
            gate_failure_severity_priority,
            filtered_gate_failed,
        )

    @staticmethod
    def _expected_severity_rank_from_failure(failure: str) -> int:
        marker = "expected <= "
        if marker not in failure:
            return 99
        severity = failure.split(marker, 1)[1].rstrip(") ").strip()
        severity_order = SEVERITY_ORDER
        return severity_order.get(severity, 99)

    @staticmethod
    def _resolve_failed_gates_view(
        summary: dict[str, Any],
        gate_failure_summary: dict[str, Any],
        gate_failure_priority: list[dict[str, Any]],
        gate_failure_severity_priority: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        """Resolve failed-gates summary and ordering from persisted report views first."""
        report_views = dict(summary.get("report_views", {}) or {})
        failed_gates_view = dict(report_views.get("only_failed_gates", {}) or {})
        persisted_summary = dict(failed_gates_view.get("summary", {}) or {})
        persisted_priority = list(failed_gates_view.get("priority", []) or [])
        persisted_severity_priority = list(failed_gates_view.get("severity_priority", []) or [])

        if persisted_summary:
            gate_failure_summary = persisted_summary
        if persisted_priority:
            gate_failure_priority = persisted_priority
        if persisted_severity_priority:
            gate_failure_severity_priority = persisted_severity_priority

        if not gate_failure_severity_priority:
            gate_failure_severity_priority = GateEvaluator.build_gate_failure_severity_priority(gate_failure_summary)

        return gate_failure_summary, gate_failure_priority, gate_failure_severity_priority

    @staticmethod
    def _filter_failed_gates_view(
        gate_failure_summary: dict[str, Any],
        gate_failure_priority: list[dict[str, Any]],
        gate_failure_severity_priority: list[dict[str, Any]],
        only_expected_severity: str | None,
        resolved_only_pass_failure: str | None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
        """Apply gate filters to the normalized failed-gates view."""
        filtered_summary = dict(gate_failure_summary)
        filtered_priority = list(gate_failure_priority)
        filtered_severity_priority = list(gate_failure_severity_priority)

        if only_expected_severity:
            filtered_severity_priority = [
                row for row in filtered_severity_priority if row.get("severity") == only_expected_severity
            ]
            filtered_priority = [
                row for row in filtered_priority if row.get("strictest_expected_severity") == only_expected_severity
            ]
            filtered_summary["require_pass_severity_failures_by_expected_severity"] = {
                row.get("severity", "unknown"): row.get("failure_count", 0) for row in filtered_severity_priority
            }

        if resolved_only_pass_failure:
            filtered_priority = [row for row in filtered_priority if row.get("pass_name") == resolved_only_pass_failure]

        filtered_summary["require_pass_severity_failures_by_pass"] = {
            row.get("pass_name", "unknown"): list(row.get("failures", [])) for row in filtered_priority
        }
        filtered_summary["require_pass_severity_failures"] = [
            failure for row in filtered_priority for failure in row.get("failures", [])
        ]
        filtered_summary["require_pass_severity_failure_count"] = len(
            filtered_summary["require_pass_severity_failures"]
        )
        filtered_summary["require_pass_severity_failed"] = bool(filtered_summary["require_pass_severity_failures"])

        if resolved_only_pass_failure:
            severity_counts: dict[str, int] = {}
            for row in filtered_priority:
                severity = row.get("strictest_expected_severity", "unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + int(row.get("failure_count", 0))
            filtered_summary["require_pass_severity_failures_by_expected_severity"] = severity_counts
            filtered_severity_priority = GateEvaluator.build_gate_failure_severity_priority(filtered_summary)

        filtered_failed = bool(filtered_summary.get("require_pass_severity_failure_count", 0))
        return filtered_summary, filtered_priority, filtered_severity_priority, filtered_failed

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
        filtered_payload = dict(payload)
        filtered_payload["mutations"] = filtered_mutations
        filtered_payload["summary"] = {
            **filtered_summary,
            "only_mismatches": True,
            "filtered_passes": filtered_passes,
            "mismatch_count_by_pass": mismatch_counts_by_pass,
            "mismatch_observables_by_pass": mismatch_observables_by_pass,
        }
        filtered_payload["only_mismatches_view"] = {
            "passes": filtered_passes,
            "counts_by_pass": mismatch_counts_by_pass,
            "observables_by_pass": mismatch_observables_by_pass,
            "priority": persisted_mismatch_priority,
            "severity_rows": mismatch_severity_rows,
            "pass_context": mismatch_pass_context,
            "degraded_passes": mismatch_degraded_passes,
            "requested_validation_mode": requested_validation_mode,
            "effective_validation_mode": effective_validation_mode,
            "degraded_validation": degraded_validation,
            "failed_gates": failed_gates,
        }
        filtered_payload["gate_evaluation"] = gate_evaluation
        filtered_payload["gate_failures"] = gate_failure_summary
        filtered_payload["gate_failure_priority"] = gate_failure_priority
        filtered_payload["gate_failure_severity_priority"] = gate_failure_severity_priority
        return filtered_payload

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
        return {
            "only_pass": resolved_only_pass,
            "only_status": only_status,
            "only_degraded": only_degraded,
            "only_failed_gates": only_failed_gates,
            "only_risky_passes": only_risky_passes,
            "only_uncovered_passes": only_uncovered_passes,
            "only_covered_passes": only_covered_passes,
            "only_clean_passes": only_clean_passes,
            "only_structural_risk": only_structural_risk,
            "only_symbolic_risk": only_symbolic_risk,
            "only_mismatches": only_mismatches,
            "min_severity": min_severity,
            "only_expected_severity": only_expected_severity,
            "only_pass_failure": resolved_only_pass_failure,
        }
