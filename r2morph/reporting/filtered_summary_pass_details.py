"""Pass metadata and evidence population helpers for filtered summaries."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_helpers import _pass_evidence_from_row, _sort_pass_evidence


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
                _pass_evidence_from_row(row.get("pass_name"), row)
                for row in summary_general_pass_rows
                if row.get("pass_name") and (not visible_passes or row.get("pass_name") in visible_passes)
            ]
        )
    if not filtered_summary["pass_evidence"] and filtered_summary["normalized_pass_results"]:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                _pass_evidence_from_row(row.get("pass_name"), row)
                for row in filtered_summary["normalized_pass_results"]
                if row.get("pass_name")
            ]
        )
    if not filtered_summary["pass_evidence"] and normalized_pass_map:
        filtered_summary["pass_evidence"] = _sort_pass_evidence(
            [
                _pass_evidence_from_row(pass_name, row)
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
