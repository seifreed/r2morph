"""Projection-oriented report helpers extracted from core.report_helpers."""

from __future__ import annotations

from typing import Any


def _summarize_pass_capability_rows(
    pass_capabilities: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a compact triage-oriented capabilities summary."""
    rows = []
    for pass_name, capabilities in pass_capabilities.items():
        runtime = dict(capabilities.get("runtime", {}) or {})
        symbolic = dict(capabilities.get("symbolic", {}) or {})
        rows.append(
            {
                "pass_name": pass_name,
                "runtime_recommended": bool(runtime.get("recommended", False)),
                "symbolic_recommended": bool(symbolic.get("recommended", False)),
                "symbolic_confidence": symbolic.get("confidence", "unknown"),
            }
        )
    rows.sort(
        key=lambda item: (
            0 if item["runtime_recommended"] else 1,
            0 if item["symbolic_recommended"] else 1,
            item["pass_name"],
        )
    )
    return rows


def _build_pass_capability_summary_map(
    rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index capability rows by pass name."""
    return {str(row.get("pass_name")): dict(row) for row in rows if row.get("pass_name")}


def _build_pass_region_evidence_map(
    pass_results: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Persist compact symbolic region evidence by pass for report consumers."""
    region_map: dict[str, list[dict[str, Any]]] = {}
    for pass_name, pass_result in pass_results.items():
        evidence = dict(pass_result.get("evidence_summary", {}) or {})
        symbolic_regions = list(evidence.get("symbolic_regions", []) or [])
        if not symbolic_regions:
            continue
        region_map[pass_name] = [
            {
                "start_address": row.get("start_address"),
                "end_address": row.get("end_address"),
                "equivalent": bool(row.get("equivalent", False)),
                "mismatch_count": int(row.get("mismatch_count", len(row.get("mismatches", [])))),
                "mismatches": list(row.get("mismatches", [])),
                "step_strategy": row.get("step_strategy"),
                "region_exit_equivalent": (
                    row.get("original_region_exit_address") == row.get("mutated_region_exit_address")
                    and row.get("original_region_exit_address") is not None
                ),
                "original_region_exit_address": row.get("original_region_exit_address"),
                "mutated_region_exit_address": row.get("mutated_region_exit_address"),
                "original_trace_length": int(row.get("original_trace_length", 0)),
                "mutated_trace_length": int(row.get("mutated_trace_length", 0)),
                "original_region_exit_steps": int(row.get("original_region_exit_steps", 0)),
                "mutated_region_exit_steps": int(row.get("mutated_region_exit_steps", 0)),
            }
            for row in symbolic_regions
        ]
    return region_map


def _summarize_normalized_pass_results(
    pass_results: dict[str, Any],
    *,
    pass_triage_map: dict[str, Any],
    pass_capability_summary_map: dict[str, Any],
    validation_role_map: dict[str, Any],
    pass_evidence_map: dict[str, Any],
    pass_symbolic_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a compact normalized per-pass view for tooling/report consumers."""
    rows: list[dict[str, Any]] = []
    for pass_name in sorted(pass_results):
        symbolic_summary = dict(pass_symbolic_summary.get(pass_name, {}) or {})
        evidence = dict(pass_evidence_map.get(pass_name, {}) or {})
        triage = dict(pass_triage_map.get(pass_name, {}) or {})
        capability = dict(pass_capability_summary_map.get(pass_name, {}) or {})
        validation_context = dict(validation_role_map.get(pass_name, {}) or {})
        rows.append(
            {
                "pass_name": pass_name,
                "status": pass_results.get(pass_name, {}).get("status", "unknown"),
                "mutations_applied": int(pass_results.get(pass_name, {}).get("mutations_applied", 0)),
                "severity": symbolic_summary.get("severity", triage.get("severity", "not-requested")),
                "issue_count": int(symbolic_summary.get("issue_count", 0)),
                "structural_issue_count": int(evidence.get("structural_issue_count", 0)),
                "symbolic_binary_mismatched_regions": int(evidence.get("symbolic_binary_mismatched_regions", 0)),
                "changed_region_count": int(evidence.get("changed_region_count", 0)),
                "changed_bytes": int(evidence.get("changed_bytes", 0)),
                "runtime_recommended": bool(capability.get("runtime_recommended", False)),
                "symbolic_recommended": bool(capability.get("symbolic_recommended", False)),
                "symbolic_confidence": capability.get("symbolic_confidence", "unknown"),
                "role": validation_context.get("role", "requested-mode"),
                "symbolic_requested": int(symbolic_summary.get("symbolic_requested", 0)),
                "observable_match": int(symbolic_summary.get("observable_match", 0)),
                "observable_mismatch": int(symbolic_summary.get("observable_mismatch", 0)),
                "bounded_only": int(symbolic_summary.get("bounded_only", 0)),
                "without_coverage": int(symbolic_summary.get("without_coverage", 0)),
            }
        )
    return rows
