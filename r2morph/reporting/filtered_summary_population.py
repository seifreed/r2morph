"""Filtered-summary population helpers.

These helpers populate the mutable filtered_summary structure after the
section payloads are resolved.
"""

from typing import Any

from r2morph.reporting.filtered_summary_symbolic import (
    _populate_filtered_summary_symbolic_sections,
    _populate_symbolic_coverage_and_severity,
    _populate_symbolic_issue_passes,
)
from r2morph.reporting.report_helpers import _sort_pass_evidence, _summary_first, _visible_rows
from r2morph.reporting.report_view_resolution import _resolve_summary_pass_sources


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
    if not filtered_summary["pass_symbolic_summary"] and filtered_summary["pass_evidence"]:
        for row in filtered_summary["pass_evidence"]:
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
    if not filtered_summary["symbolic_severity_by_pass"] and filtered_summary["pass_symbolic_summary"]:
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
    _populate_symbolic_coverage_and_severity(
        filtered_summary=filtered_summary,
        by_pass=by_pass,
        degraded_passes=degraded_passes,
        only_degraded=only_degraded,
        summary_symbolic_coverage_map=summary_symbolic_coverage_map,
        summary_symbolic_severity_map=summary_symbolic_severity_map,
        pass_results=pass_results,
    )

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
    _apply_risk_filters(
        filtered_summary=filtered_summary,
        selected_risk_pass_names=selected_risk_pass_names,
        only_risky_filters=only_risky_filters,
    )

    if not filtered_summary["symbolic_issue_passes"] and by_pass:
        filtered_summary["symbolic_issue_passes"] = [
            {
                "pass_name": pass_name,
                "severity": (
                    "mismatch"
                    if pass_stats["observable_mismatch"] > 0
                    else "without-coverage" if pass_stats["without_coverage"] > 0 else "bounded-only"
                ),
                "observable_mismatch": pass_stats["observable_mismatch"],
                "without_coverage": pass_stats["without_coverage"],
                "bounded_only": pass_stats["bounded_only"],
            }
            for pass_name, pass_stats in sorted(by_pass.items())
            if pass_stats["observable_mismatch"] > 0 or pass_stats["without_coverage"] > 0 or pass_stats["bounded_only"] > 0
        ]
    if not filtered_summary["symbolic_coverage_by_pass"] and by_pass:
        filtered_summary["symbolic_coverage_by_pass"] = [
            {
                "pass_name": pass_name,
                "symbolic_requested": pass_stats["symbolic_requested"],
                "observable_match": pass_stats["observable_match"],
                "observable_mismatch": pass_stats["observable_mismatch"],
                "bounded_only": pass_stats["bounded_only"],
                "without_coverage": pass_stats["without_coverage"],
            }
            for pass_name, pass_stats in sorted(by_pass.items())
            if pass_stats["symbolic_requested"] > 0
        ]
    if by_pass and (
        not filtered_summary["symbolic_severity_by_pass"]
        or all(row.get("severity") == "not-requested" for row in filtered_summary["symbolic_severity_by_pass"])
    ):
        filtered_summary["symbolic_severity_by_pass"] = [
            {
                "pass_name": pass_name,
                "severity": (
                    "mismatch"
                    if pass_stats["observable_mismatch"] > 0
                    else "without-coverage" if pass_stats["without_coverage"] > 0 else "bounded-only"
                ),
                "issue_count": pass_stats["observable_mismatch"]
                + pass_stats["without_coverage"]
                + pass_stats["bounded_only"],
                "symbolic_requested": pass_stats["symbolic_requested"],
            }
            for pass_name, pass_stats in sorted(by_pass.items())
            if pass_stats["symbolic_requested"] > 0
        ]

    return degradation_roles
