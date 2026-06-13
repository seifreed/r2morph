"""Filtered-summary section and population helpers.

Leaf detail-builders for filtered report payloads, extracted verbatim from
filtered_summary_builder.py -- no logic changes. These functions form a
one-directional layer: the orchestrating builders depend on them, never the
reverse. Symbolic-specific helpers live in filtered_summary_symbolic.
"""

from typing import Any

from r2morph.reporting.filtered_summary_symbolic import (
    _populate_filtered_summary_symbolic_sections,
    _populate_symbolic_coverage_and_severity,
    _populate_symbolic_issue_passes,
)
from r2morph.reporting.report_helpers import _sort_pass_evidence, _summary_first, _visible_rows
from r2morph.reporting.report_view_resolution import (
    _resolve_general_report_views,
    _resolve_summary_pass_sources,
)


def _build_filtered_summary_gate_sections(
    *,
    summary: dict[str, Any],
    gate_evaluation: dict[str, Any],
    gate_failure_summary: dict[str, Any],
    gate_failure_priority: list[dict[str, Any]],
    gate_failure_severity_priority: list[dict[str, Any]],
    failed_gates: bool,
) -> dict[str, Any]:
    """Build filtered_summary gate-related sections from persisted report views first."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    general_gates = resolved_general_views["general_gates"]
    persisted_view = dict(report_views.get("only_failed_gates", {}) or {})
    summary_payload = dict(
        persisted_view.get("summary", {})
        or general_gates.get("summary", {})
        or gate_failure_summary
        or general_gates.get("compact_summary", {})
    )
    priority_payload = list(persisted_view.get("priority", []) or gate_failure_priority)
    severity_payload = list(
        persisted_view.get("severity_priority", [])
        or general_gates.get("severity_priority", [])
        or gate_failure_severity_priority
    )
    compact_summary = dict(persisted_view.get("compact_summary", {}) or general_gates.get("compact_summary", {}) or {})
    final_rows = list(persisted_view.get("final_rows", []) or [])
    compact_rows = list(persisted_view.get("compact_rows", []) or [])
    final_by_pass = dict(persisted_view.get("final_by_pass", {}) or {})
    if not final_rows and priority_payload:
        if final_by_pass:
            final_rows = [dict(final_by_pass[pass_name]) for pass_name in sorted(final_by_pass)]
        else:
            final_rows = [
                {
                    "pass_name": str(row.get("pass_name", "")),
                    "failure_count": int(row.get("failure_count", 0)),
                    "strictest_expected_severity": row.get("strictest_expected_severity", "unknown"),
                    "role": row.get("role", "requested-mode"),
                    "failed": bool(row.get("failures")),
                    "failures": list(row.get("failures", [])),
                }
                for row in priority_payload
                if row.get("pass_name")
            ]
    elif final_rows:
        priority_by_pass = {
            str(row.get("pass_name", "")): dict(row) for row in priority_payload if row.get("pass_name")
        }
        enriched_final_rows = []
        for row in final_rows:
            pass_name = str(row.get("pass_name", ""))
            priority_row = priority_by_pass.get(pass_name, {})
            enriched = dict(row)
            if "failures" not in enriched and priority_row.get("failures") is not None:
                enriched["failures"] = list(priority_row.get("failures", []))
            enriched_final_rows.append(enriched)
        final_rows = enriched_final_rows
    if not compact_summary:
        compact_summary = {
            "failed": bool(persisted_view.get("failed", False) or failed_gates),
            "failure_count": int(
                persisted_view.get("failure_count", 0) or summary_payload.get("require_pass_severity_failure_count", 0)
            ),
            "pass_count": int(persisted_view.get("pass_count", 0)),
            "expected_severity_counts": dict(persisted_view.get("expected_severity_counts", {}) or {}),
            "severity_priority": severity_payload,
            "passes": list(persisted_view.get("passes", []) or []),
        }
    section: dict[str, Any] = {
        "failed_gates": failed_gates or bool(persisted_view.get("failed", False)),
        "gate_failure_priority": priority_payload,
        "gate_failure_severity_priority": severity_payload,
        "gate_failure_final_rows": final_rows,
        "gate_failure_final_by_pass": final_by_pass,
        "gate_failure_compact_rows": compact_rows,
        "gate_failure_compact_by_pass": dict(persisted_view.get("compact_by_pass", {}) or {}),
        "gate_failure_compact_summary": compact_summary,
    }
    if gate_evaluation:
        section["gate_evaluation"] = gate_evaluation
    if summary_payload:
        section["gate_failures"] = summary_payload
    return section


def _build_filtered_summary_risk_coverage_sections(
    *,
    summary: dict[str, Any],
    risky_pass_names: set[str],
    structural_risk_pass_names: set[str],
    symbolic_risk_pass_names: set[str],
    covered_pass_names: set[str],
    uncovered_pass_names: set[str],
    clean_pass_names: set[str],
) -> dict[str, Any]:
    """Build filtered_summary risk/coverage sections from persisted summary first."""
    report_views = dict(summary.get("report_views", {}) or {})
    general_renderer_state = dict(report_views.get("general_renderer_state", {}) or {})
    pass_risk_buckets = dict(_summary_first(summary, "pass_risk_buckets", {}) or {})
    pass_coverage_buckets = dict(_summary_first(summary, "pass_coverage_buckets", {}) or {})
    general_filter_views = dict(report_views.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("general_filter_views"):
        general_filter_views = dict(general_renderer_state.get("general_filter_views", {}) or {})
    if not general_filter_views and general_renderer_state.get("filter_views"):
        general_filter_views = dict(general_renderer_state.get("filter_views", {}) or {})
    risky = sorted(pass_risk_buckets.get("risky", list(risky_pass_names)) or list(risky_pass_names))
    if not risky and general_filter_views.get("risky"):
        risky = sorted(str(name) for name in general_filter_views.get("risky", []) if name)
    structural = sorted(
        pass_risk_buckets.get("structural", list(structural_risk_pass_names)) or list(structural_risk_pass_names)
    )
    if not structural and general_filter_views.get("structural_risk"):
        structural = sorted(str(name) for name in general_filter_views.get("structural_risk", []) if name)
    symbolic = sorted(
        pass_risk_buckets.get("symbolic", list(symbolic_risk_pass_names)) or list(symbolic_risk_pass_names)
    )
    if not symbolic and general_filter_views.get("symbolic_risk"):
        symbolic = sorted(str(name) for name in general_filter_views.get("symbolic_risk", []) if name)
    clean = sorted(pass_risk_buckets.get("clean", list(clean_pass_names)) or list(clean_pass_names))
    if not clean and general_filter_views.get("clean"):
        clean = sorted(str(name) for name in general_filter_views.get("clean", []) if name)
    covered = sorted(pass_coverage_buckets.get("covered", list(covered_pass_names)) or list(covered_pass_names))
    if not covered and general_filter_views.get("covered"):
        covered = sorted(str(name) for name in general_filter_views.get("covered", []) if name)
    uncovered = sorted(pass_coverage_buckets.get("uncovered", list(uncovered_pass_names)) or list(uncovered_pass_names))
    if not uncovered and general_filter_views.get("uncovered"):
        uncovered = sorted(str(name) for name in general_filter_views.get("uncovered", []) if name)
    clean_only = sorted(pass_coverage_buckets.get("clean_only", list(clean_pass_names)) or list(clean_pass_names))
    return {
        "pass_coverage_buckets": {
            "covered": covered,
            "uncovered": uncovered,
            "clean_only": clean_only,
        },
        "pass_risk_buckets": {
            "risky": risky,
            "structural": structural,
            "symbolic": symbolic,
            "clean": clean,
            "covered": covered,
            "uncovered": uncovered,
        },
        "risky_passes": risky,
        "structural_risk_passes": structural,
        "symbolic_risk_passes": symbolic,
        "covered_passes": covered,
        "uncovered_passes": uncovered,
        "clean_passes": clean,
    }


def _build_filtered_summary_degradation_sections(
    *,
    summary: dict[str, Any],
    validation_policy: dict[str, Any] | None,
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_validation: bool,
    degraded_passes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build filtered_summary degradation/validation-mode sections."""
    resolved_general_views = _resolve_general_report_views(summary)
    report_views = resolved_general_views["report_views"]
    validation_adjustments = dict(summary.get("validation_adjustments", {}) or {})
    general_degradation = resolved_general_views["general_degradation"]
    persisted_adjustments = dict(report_views.get("validation_adjustments", {}) or {})
    degradation_roles = dict(summary.get("degradation_roles", {}) or {})
    section: dict[str, Any] = {
        "requested_validation_mode": requested_validation_mode,
        "validation_mode": effective_validation_mode,
        "degraded_validation": degraded_validation,
        "degraded_passes": degraded_passes,
        "degradation_roles": degradation_roles,
    }
    if validation_policy is not None:
        section["validation_policy"] = validation_policy
    if general_degradation.get("summary"):
        section["validation_adjustments"] = dict(general_degradation.get("summary", {}))
    elif validation_adjustments:
        section["validation_adjustments"] = validation_adjustments
    if persisted_adjustments:
        if persisted_adjustments.get("by_pass"):
            section["validation_adjustment_by_pass"] = dict(persisted_adjustments.get("by_pass", {}))
        if persisted_adjustments.get("compact_by_pass"):
            section["validation_adjustment_compact_by_pass"] = dict(persisted_adjustments.get("compact_by_pass", {}))
        if persisted_adjustments.get("rows"):
            section["validation_adjustment_rows"] = list(persisted_adjustments.get("rows", []))
        if persisted_adjustments.get("compact_rows"):
            section["validation_adjustment_compact_rows"] = list(persisted_adjustments.get("compact_rows", []))
        if persisted_adjustments.get("summary"):
            section["validation_adjustment_summary"] = dict(persisted_adjustments.get("summary", {}))
        if persisted_adjustments.get("compact_summary"):
            section["validation_adjustment_compact_summary"] = dict(persisted_adjustments.get("compact_summary", {}))
        elif persisted_adjustments.get("summary"):
            section["validation_adjustment_compact_summary"] = dict(persisted_adjustments.get("summary", {}))
    elif general_degradation:
        if general_degradation.get("rows"):
            section["validation_adjustment_rows"] = list(general_degradation.get("rows", []))
        if general_degradation.get("compact_rows"):
            section["validation_adjustment_compact_rows"] = list(general_degradation.get("compact_rows", []))
        if general_degradation.get("summary"):
            section["validation_adjustment_summary"] = dict(general_degradation.get("summary", {}))
            section["validation_adjustment_compact_summary"] = dict(general_degradation.get("summary", {}))
    elif validation_adjustments:
        section["validation_adjustment_compact_summary"] = {
            "requested_validation_mode": requested_validation_mode,
            "effective_validation_mode": effective_validation_mode,
            "degraded_validation": degraded_validation,
        }
    return section


def _populate_pass_capabilities_and_context(
    *,
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    pass_support: dict[str, Any],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degradation_roles: dict[str, int],
    normalized_pass_map: dict[str, dict[str, Any]],
    summary_pass_capabilities: dict[str, Any],
    summary_pass_validation_context: dict[str, Any],
) -> None:
    """Populate pass_capabilities and pass_validation_context for each visible pass."""
    for pass_name in filtered_summary["passes"]:
        capabilities = summary_pass_capabilities.get(pass_name)
        if capabilities is None:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                capabilities = {
                    "runtime": {"recommended": bool(normalized_row.get("runtime_recommended", False))},
                    "symbolic": {
                        "recommended": bool(normalized_row.get("symbolic_recommended", False)),
                        "confidence": normalized_row.get("symbolic_confidence", "unknown"),
                    },
                }
        if capabilities is None:
            support = pass_support.get(pass_name)
            if support:
                capabilities = support.get("validator_capabilities", {})
        if capabilities:
            filtered_summary["pass_capabilities"][pass_name] = dict(capabilities)

        context = summary_pass_validation_context.get(
            pass_name, pass_results.get(pass_name, {}).get("validation_context")
        )
        if not context:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                context = {
                    "role": normalized_row.get("role", "requested-mode"),
                    "requested_validation_mode": requested_validation_mode,
                    "effective_validation_mode": effective_validation_mode,
                    "degraded_execution": normalized_row.get("role") == "executed-under-degraded-mode",
                    "degradation_triggered_by_pass": normalized_row.get("role") == "degradation-trigger",
                }
        if context:
            context_payload = dict(context)
            context_payload["role"] = (
                "degradation-trigger"
                if context.get("degradation_triggered_by_pass")
                else "executed-under-degraded-mode" if context.get("degraded_execution") else "requested-mode"
            )
            filtered_summary["pass_validation_context"][pass_name] = context_payload

    if not degradation_roles:
        for context in filtered_summary["pass_validation_context"].values():
            role = context.get("role")
            if role:
                degradation_roles[role] = degradation_roles.get(role, 0) + 1


def _populate_triage_and_results(
    *,
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    summary_pass_triage_map: dict[str, Any],
    summary_normalized_pass_results: list[dict[str, Any]],
    summary_pass_capability_summary_map: dict[str, Any],
    summary_validation_role_map: dict[str, Any],
    summary_report_views: dict[str, Any],
    summary_general_pass_rows: list[dict[str, Any]],
    summary_general_passes: list[dict[str, Any]],
    summary_discarded_mutation_summary: dict[str, Any],
    summary_discarded_view: dict[str, Any],
    summary_discarded_mutation_priority: list[dict[str, Any]],
    summary_general_discards: dict[str, Any],
) -> None:
    """Populate triage rows, normalized results, capability summary, and validation role rows."""
    pass_triage_rows = list(
        _summary_first(summary, "pass_triage_rows", summary_report_views.get("triage_priority", [])) or []
    )
    if pass_triage_rows:
        filtered_summary["pass_triage_rows"] = _visible_rows(
            pass_triage_rows,
            set(filtered_summary["passes"]),
        )
    elif summary_pass_triage_map:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_triage_rows"] = [
            dict(row)
            for pass_name, row in summary_pass_triage_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    if summary_normalized_pass_results:
        filtered_summary["normalized_pass_results"] = _visible_rows(
            summary_normalized_pass_results,
            set(filtered_summary["passes"]),
        )
    elif summary_general_pass_rows:
        filtered_summary["normalized_pass_results"] = _visible_rows(
            summary_general_pass_rows,
            set(filtered_summary["passes"]),
        )
    elif summary_general_passes:
        filtered_summary["normalized_pass_results"] = _visible_rows(
            summary_general_passes,
            set(filtered_summary["passes"]),
        )

    capability_rows = list(summary.get("pass_capability_summary", []))
    if capability_rows:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capability_summary"] = [
            dict(row) for row in capability_rows if not visible_passes or row.get("pass_name") in visible_passes
        ]
    elif summary_pass_capability_summary_map:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capability_summary"] = [
            dict(row)
            for pass_name, row in summary_pass_capability_summary_map.items()
            if not visible_passes or pass_name in visible_passes
        ]
    elif summary_general_pass_rows:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capability_summary"] = [
            {
                "pass_name": str(row.get("pass_name")),
                "runtime_recommended": bool(row.get("runtime_recommended", False)),
                "symbolic_recommended": bool(row.get("symbolic_recommended", False)),
                "symbolic_confidence": row.get("symbolic_confidence", "unknown"),
            }
            for row in summary_general_pass_rows
            if row.get("pass_name") and (not visible_passes or row.get("pass_name") in visible_passes)
        ]

    validation_role_rows = list(summary.get("validation_role_rows", []))
    if validation_role_rows:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["validation_role_rows"] = [
            dict(row) for row in validation_role_rows if not visible_passes or row.get("pass_name") in visible_passes
        ]
    elif summary_validation_role_map:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["validation_role_rows"] = [
            dict(row)
            for pass_name, row in summary_validation_role_map.items()
            if not visible_passes or pass_name in visible_passes
        ]

    _populate_filtered_summary_discarded_sections(
        filtered_summary=filtered_summary,
        summary_discarded_mutation_summary=summary_discarded_mutation_summary,
        summary_discarded_view=summary_discarded_view,
        summary_discarded_mutation_priority=summary_discarded_mutation_priority,
    )
    if "discarded_mutation_compact_summary" not in filtered_summary and summary_general_discards.get("summary"):
        filtered_summary["discarded_mutation_compact_summary"] = dict(summary_general_discards.get("summary", {}))
    if "discarded_mutation_compact_rows" not in filtered_summary and summary_general_discards.get("rows"):
        filtered_summary["discarded_mutation_compact_rows"] = list(summary_general_discards.get("rows", []))


def _populate_pass_evidence(
    *,
    filtered_summary: dict[str, Any],
    pass_results: dict[str, Any],
    normalized_pass_map: dict[str, dict[str, Any]],
    selected_risk_pass_names: set[str],
    resolved_only_pass: str | None,
    only_risky_filters: bool,
    summary_pass_region_evidence_map: dict[str, Any],
    summary_pass_evidence_map: dict[str, Any],
    summary_general_pass_rows: list[dict[str, Any]],
) -> None:
    """Populate pass_evidence and pass_region_evidence_map with fallback chains."""
    visible_passes = set(filtered_summary["passes"])
    if summary_pass_region_evidence_map:
        filtered_summary["pass_region_evidence_map"] = {
            pass_name: list(rows)
            for pass_name, rows in summary_pass_region_evidence_map.items()
            if not visible_passes or pass_name in visible_passes
        }
    if not filtered_summary["pass_evidence"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(pass_results.get(pass_name, {}).get("evidence_summary", {}))
                for pass_name in filtered_summary["passes"]
                if pass_results.get(pass_name, {}).get("evidence_summary")
            ]
        )
    if not filtered_summary["pass_evidence"] and summary_pass_evidence_map:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(row)
                for pass_name, row in summary_pass_evidence_map.items()
                if (not visible_passes or pass_name in visible_passes) and row.get("pass_name")
            ]
        )
    if not filtered_summary["pass_evidence"] and summary_general_pass_rows:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                {
                    "pass_name": row.get("pass_name"),
                    "changed_region_count": row.get("changed_region_count", 0),
                    "changed_bytes": row.get("changed_bytes", 0),
                    "structural_issue_count": row.get("structural_issue_count", 0),
                    "symbolic_binary_mismatched_regions": row.get("symbolic_binary_mismatched_regions", 0),
                }
                for row in summary_general_pass_rows
                if row.get("pass_name") and (not visible_passes or row.get("pass_name") in visible_passes)
            ]
        )
    if not filtered_summary["pass_evidence"] and filtered_summary["normalized_pass_results"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                {
                    "pass_name": row.get("pass_name"),
                    "changed_region_count": row.get("changed_region_count", 0),
                    "changed_bytes": row.get("changed_bytes", 0),
                    "structural_issue_count": row.get("structural_issue_count", 0),
                    "symbolic_binary_mismatched_regions": row.get("symbolic_binary_mismatched_regions", 0),
                }
                for row in filtered_summary["normalized_pass_results"]
                if row.get("pass_name")
            ]
        )
    if not filtered_summary["pass_evidence"] and normalized_pass_map:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                {
                    "pass_name": pass_name,
                    "changed_region_count": row.get("changed_region_count", 0),
                    "changed_bytes": row.get("changed_bytes", 0),
                    "structural_issue_count": row.get("structural_issue_count", 0),
                    "symbolic_binary_mismatched_regions": row.get("symbolic_binary_mismatched_regions", 0),
                }
                for pass_name, row in normalized_pass_map.items()
                if pass_name in set(filtered_summary["passes"])
            ]
        )
    if only_risky_filters and not filtered_summary["pass_evidence"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                dict(pass_results.get(pass_name, {}).get("evidence_summary", {}))
                for pass_name in sorted(selected_risk_pass_names)
                if pass_results.get(pass_name, {}).get("evidence_summary")
                and (resolved_only_pass is None or pass_name == resolved_only_pass)
            ]
        )


def _apply_risk_filters(
    *,
    filtered_summary: dict[str, Any],
    selected_risk_pass_names: set[str],
    only_risky_filters: bool,
) -> None:
    """Apply risk-based filtering and final symbolic summary fallbacks."""
    if only_risky_filters:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [row for row in filtered_summary["pass_evidence"] if row.get("pass_name") in selected_risk_pass_names]
        )
        filtered_summary["symbolic_issue_passes"] = [
            row for row in filtered_summary["symbolic_issue_passes"] if row.get("pass_name") in selected_risk_pass_names
        ]
        filtered_summary["symbolic_coverage_by_pass"] = [
            row
            for row in filtered_summary["symbolic_coverage_by_pass"]
            if row.get("pass_name") in selected_risk_pass_names
        ]
        filtered_summary["symbolic_severity_by_pass"] = [
            row
            for row in filtered_summary["symbolic_severity_by_pass"]
            if row.get("pass_name") in selected_risk_pass_names
        ]
        filtered_summary["pass_capabilities"] = {
            pass_name: capabilities
            for pass_name, capabilities in filtered_summary["pass_capabilities"].items()
            if pass_name in selected_risk_pass_names
        }
        filtered_summary["pass_validation_context"] = {
            pass_name: context
            for pass_name, context in filtered_summary["pass_validation_context"].items()
            if pass_name in selected_risk_pass_names
        }
        filtered_summary["pass_symbolic_summary"] = {
            pass_name: summary_row
            for pass_name, summary_row in filtered_summary["pass_symbolic_summary"].items()
            if pass_name in selected_risk_pass_names
        }

    if not filtered_summary["pass_symbolic_summary"]:
        for row in filtered_summary["symbolic_coverage_by_pass"]:
            pass_name = row.get("pass_name")
            if not pass_name:
                continue
            filtered_summary["pass_symbolic_summary"][pass_name] = {
                **row,
                "issues": [
                    issue for issue in filtered_summary["symbolic_issue_passes"] if issue.get("pass_name") == pass_name
                ],
            }
    if not filtered_summary["pass_symbolic_summary"] and filtered_summary["normalized_pass_results"]:
        for row in filtered_summary["normalized_pass_results"]:
            pass_name = row.get("pass_name")
            if not pass_name:
                continue
            filtered_summary["pass_symbolic_summary"][str(pass_name)] = {
                "pass_name": str(pass_name),
                "severity": row.get("severity", "not-requested"),
                "issue_count": row.get("issue_count", 0),
                "symbolic_requested": row.get("symbolic_requested", 0),
                "observable_match": row.get("observable_match", 0),
                "observable_mismatch": row.get("observable_mismatch", 0),
                "bounded_only": row.get("bounded_only", 0),
                "without_coverage": row.get("without_coverage", 0),
                "issues": [],
            }
    if only_risky_filters and not filtered_summary["symbolic_severity_by_pass"]:
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": summary_row.get("severity", "not-requested"),
                "issue_count": summary_row.get("issue_count", 0),
                "symbolic_requested": summary_row.get("symbolic_requested", 0),
            }
            for pass_name, summary_row in sorted(
                filtered_summary["pass_symbolic_summary"].items(),
                key=lambda item: item[0],
            )
        ]


def _populate_filtered_summary_pass_sections(
    *,
    filtered_summary: dict[str, Any],
    summary: dict[str, Any],
    pass_results: dict[str, Any],
    pass_support: dict[str, Any],
    requested_validation_mode: str | None,
    effective_validation_mode: str | None,
    degraded_passes: list[dict[str, Any]],
    degradation_roles: dict[str, int],
    by_pass: dict[str, dict[str, int]],
    normalized_pass_map: dict[str, dict[str, Any]],
    selected_risk_pass_names: set[str],
    resolved_only_pass: str | None,
    only_risky_filters: bool,
    only_degraded: bool,
) -> dict[str, int]:
    """Populate filtered_summary pass-related sections using summary-first data."""
    summary_sources = _resolve_summary_pass_sources(summary)
    summary_pass_validation_context = summary_sources["pass_validation_context"]
    summary_pass_symbolic_summary = summary_sources["pass_symbolic_summary"]
    summary_pass_capabilities = summary_sources["pass_capabilities"]
    summary_pass_evidence_map = summary_sources["pass_evidence_map"]
    summary_pass_region_evidence_map = summary_sources["pass_region_evidence_map"]
    summary_pass_triage_map = summary_sources["pass_triage_map"]
    summary_normalized_pass_results = summary_sources["normalized_pass_results"]
    summary_symbolic_issue_map = summary_sources["symbolic_issue_map"]
    summary_symbolic_coverage_map = summary_sources["symbolic_coverage_map"]
    summary_symbolic_severity_map = summary_sources["symbolic_severity_map"]
    summary_pass_capability_summary_map = summary_sources["pass_capability_summary_map"]
    summary_validation_role_map = summary_sources["validation_role_map"]
    summary_discarded_mutation_summary = summary_sources["discarded_mutation_summary"]
    summary_discarded_mutation_priority = summary_sources["discarded_mutation_priority"]
    summary_pass_evidence_compact = summary_sources["pass_evidence_compact"]
    summary_report_views = summary_sources["report_views"]
    summary_discarded_view = summary_sources["discarded_view"]
    summary_general_passes = summary_sources["general_passes"]
    summary_general_pass_rows = summary_sources["general_pass_rows"]
    summary_general_symbolic = summary_sources["general_symbolic"]
    summary_general_discards = summary_sources["general_discards"]

    # 1. Populate pass capabilities and validation context
    _populate_pass_capabilities_and_context(
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        pass_support=pass_support,
        requested_validation_mode=requested_validation_mode,
        effective_validation_mode=effective_validation_mode,
        degradation_roles=degradation_roles,
        normalized_pass_map=normalized_pass_map,
        summary_pass_capabilities=summary_pass_capabilities,
        summary_pass_validation_context=summary_pass_validation_context,
    )

    # 2. Delegate to _populate_filtered_summary_symbolic_sections (kept in main)
    _populate_filtered_summary_symbolic_sections(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
        degraded_passes=degraded_passes,
        only_degraded=only_degraded,
        summary_symbolic_issue_map=summary_symbolic_issue_map,
        summary_symbolic_coverage_map=summary_symbolic_coverage_map,
        summary_symbolic_severity_map=summary_symbolic_severity_map,
        summary_pass_symbolic_summary=summary_pass_symbolic_summary,
    )

    # 3. Populate pass_evidence and symbolic_issue_passes
    _populate_symbolic_issue_passes(
        filtered_summary=filtered_summary,
        summary=summary,
        pass_results=pass_results,
        by_pass=by_pass,
        summary_symbolic_issue_map=summary_symbolic_issue_map,
        summary_pass_evidence_compact=summary_pass_evidence_compact,
        summary_pass_evidence_map=summary_pass_evidence_map,
        summary_general_symbolic=summary_general_symbolic,
    )

    # 4. Populate symbolic coverage and severity
    _populate_symbolic_coverage_and_severity(
        filtered_summary=filtered_summary,
        by_pass=by_pass,
        degraded_passes=degraded_passes,
        only_degraded=only_degraded,
        summary_symbolic_coverage_map=summary_symbolic_coverage_map,
        summary_symbolic_severity_map=summary_symbolic_severity_map,
        pass_results=pass_results,
    )

    # Fallback population (kept in main)
    filtered_summary["degradation_roles"] = degradation_roles
    for pass_name in filtered_summary["passes"]:
        pass_symbolic_summary = summary_pass_symbolic_summary.get(
            pass_name, pass_results.get(pass_name, {}).get("symbolic_summary")
        )
        if not pass_symbolic_summary:
            normalized_row = normalized_pass_map.get(pass_name, {})
            if normalized_row:
                pass_symbolic_summary = {
                    "pass_name": pass_name,
                    "severity": normalized_row.get("severity", "not-requested"),
                    "issue_count": normalized_row.get("issue_count", 0),
                    "symbolic_requested": normalized_row.get("symbolic_requested", 0),
                    "observable_match": normalized_row.get("observable_match", 0),
                    "observable_mismatch": normalized_row.get("observable_mismatch", 0),
                    "bounded_only": normalized_row.get("bounded_only", 0),
                    "without_coverage": normalized_row.get("without_coverage", 0),
                    "issues": [],
                }
        if pass_symbolic_summary:
            filtered_summary["pass_symbolic_summary"][pass_name] = dict(pass_symbolic_summary)

    if not filtered_summary["pass_validation_context"] and summary_pass_validation_context:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_validation_context"] = {
            pass_name: dict(context)
            for pass_name, context in summary_pass_validation_context.items()
            if not visible_passes or pass_name in visible_passes
        }
    if not filtered_summary["pass_symbolic_summary"] and summary_pass_symbolic_summary:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_symbolic_summary"] = {
            pass_name: dict(summary_row)
            for pass_name, summary_row in summary_pass_symbolic_summary.items()
            if not visible_passes or pass_name in visible_passes
        }
    if not filtered_summary["pass_capabilities"] and summary_pass_capabilities:
        visible_passes = set(filtered_summary["passes"])
        filtered_summary["pass_capabilities"] = {
            pass_name: dict(capabilities)
            for pass_name, capabilities in summary_pass_capabilities.items()
            if not visible_passes or pass_name in visible_passes
        }

    # 5. Populate triage rows, normalized results, capability summary, validation roles, discards
    _populate_triage_and_results(
        filtered_summary=filtered_summary,
        summary=summary,
        summary_pass_triage_map=summary_pass_triage_map,
        summary_normalized_pass_results=summary_normalized_pass_results,
        summary_pass_capability_summary_map=summary_pass_capability_summary_map,
        summary_validation_role_map=summary_validation_role_map,
        summary_report_views=summary_report_views,
        summary_general_pass_rows=summary_general_pass_rows,
        summary_general_passes=summary_general_passes,
        summary_discarded_mutation_summary=summary_discarded_mutation_summary,
        summary_discarded_view=summary_discarded_view,
        summary_discarded_mutation_priority=summary_discarded_mutation_priority,
        summary_general_discards=summary_general_discards,
    )

    # 6. Populate pass evidence with fallback chains
    _populate_pass_evidence(
        filtered_summary=filtered_summary,
        pass_results=pass_results,
        normalized_pass_map=normalized_pass_map,
        selected_risk_pass_names=selected_risk_pass_names,
        resolved_only_pass=resolved_only_pass,
        only_risky_filters=only_risky_filters,
        summary_pass_region_evidence_map=summary_pass_region_evidence_map,
        summary_pass_evidence_map=summary_pass_evidence_map,
        summary_general_pass_rows=summary_general_pass_rows,
    )

    # 7. Apply risk-based filters and final symbolic summary fallbacks
    _apply_risk_filters(
        filtered_summary=filtered_summary,
        selected_risk_pass_names=selected_risk_pass_names,
        only_risky_filters=only_risky_filters,
    )

    return degradation_roles


def _populate_filtered_summary_discarded_sections(
    *,
    filtered_summary: dict[str, Any],
    summary_discarded_mutation_summary: dict[str, Any],
    summary_discarded_view: dict[str, Any],
    summary_discarded_mutation_priority: list[dict[str, Any]],
) -> None:
    """Populate discarded-mutation sections with summary-first compact/final rows."""
    if summary_discarded_mutation_summary:
        filtered_summary["discarded_mutation_summary"] = summary_discarded_mutation_summary
    if summary_discarded_view:
        if summary_discarded_view.get("final_by_pass"):
            filtered_summary["discarded_mutation_final_by_pass"] = dict(summary_discarded_view.get("final_by_pass", {}))
        if summary_discarded_view.get("final_rows"):
            filtered_summary["discarded_mutation_final_rows"] = list(summary_discarded_view.get("final_rows", []))
        if summary_discarded_view.get("compact_rows"):
            filtered_summary["discarded_mutation_compact_rows"] = list(summary_discarded_view.get("compact_rows", []))
        if summary_discarded_view.get("compact_by_pass"):
            filtered_summary["discarded_mutation_compact_by_pass"] = dict(
                summary_discarded_view.get("compact_by_pass", {})
            )
        if summary_discarded_view.get("compact_by_reason"):
            filtered_summary["discarded_mutation_compact_by_reason"] = dict(
                summary_discarded_view.get("compact_by_reason", {})
            )
        if summary_discarded_view.get("compact_summary"):
            filtered_summary["discarded_mutation_compact_summary"] = dict(
                summary_discarded_view.get("compact_summary", {})
            )
    elif summary_discarded_mutation_priority:
        if "discarded_mutation_final_rows" not in filtered_summary:
            filtered_summary["discarded_mutation_final_rows"] = [
                {
                    "pass_name": row.get("pass_name"),
                    "reasons": list(row.get("reasons", {}).keys()) if isinstance(row.get("reasons"), dict) else [],
                }
                for row in summary_discarded_mutation_priority
                if row.get("pass_name")
            ]
        if "discarded_mutation_compact_rows" not in filtered_summary:
            filtered_summary["discarded_mutation_compact_rows"] = list(summary_discarded_mutation_priority)
        if "discarded_mutation_compact_by_reason" not in filtered_summary:
            by_reason: dict[str, int] = {}
            for row in summary_discarded_mutation_priority:
                reasons = row.get("reasons", {})
                if isinstance(reasons, dict):
                    for reason, count in reasons.items():
                        by_reason[reason] = by_reason.get(reason, 0) + count
            filtered_summary["discarded_mutation_compact_by_reason"] = by_reason
