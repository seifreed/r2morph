"""Filtered-summary gate section builders."""

from __future__ import annotations

from typing import Any

from r2morph.reporting.report_view_resolution import _resolve_general_report_views


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
