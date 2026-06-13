"""Report builder dispatch helpers.

The payload construction logic lives in filtered_summary_payloads.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from r2morph.reporting.filtered_summary_payloads import (
    _build_base_filtered_summary as _build_base_filtered_summary_impl,
)
from r2morph.reporting.filtered_summary_payloads import (
    _build_general_filtered_summary as _build_general_filtered_summary_impl,
)
from r2morph.reporting.filtered_summary_payloads import (
    _build_general_report_payload as _build_general_report_payload_impl,
)
from r2morph.reporting.filtered_summary_payloads import (
    _build_only_mismatches_filtered_summary as _build_only_mismatches_filtered_summary_impl,
)
from r2morph.reporting.filtered_summary_payloads import (
    _build_only_mismatches_payload as _build_only_mismatches_payload_impl,
)
from r2morph.reporting.filtered_summary_payloads import (
    _build_report_filters as _build_report_filters_impl,
)


def _build_base_filtered_summary(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return _build_base_filtered_summary_impl(*args, **kwargs)


def _build_general_filtered_summary(*args: Any, **kwargs: Any) -> tuple[dict[str, Any], dict[str, int]]:
    return _build_general_filtered_summary_impl(*args, **kwargs)


def _build_only_mismatches_filtered_summary(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return _build_only_mismatches_filtered_summary_impl(*args, **kwargs)


def _build_only_mismatches_payload(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return _build_only_mismatches_payload_impl(*args, **kwargs)


def _build_general_report_payload(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return _build_general_report_payload_impl(*args, **kwargs)


def _build_report_filters(*args: Any, **kwargs: Any) -> dict[str, object]:
    return _build_report_filters_impl(*args, **kwargs)


def _build_report_dispatch_state(
    *,
    context: dict[str, Any],
    general_state: dict[str, Any],
    payload: dict[str, Any],
    pass_results: dict[str, Any],
    only_pass: str | None,
    only_pass_failure: str | None,
    only_status: str | None,
    only_degraded: bool,
    only_failed_gates: bool,
    only_risky_passes: bool,
    only_structural_risk: bool,
    only_symbolic_risk: bool,
    only_uncovered_passes: bool,
    only_covered_passes: bool,
    only_clean_passes: bool,
    output: Path | None,
    summary_only: bool,
    require_results: bool,
    min_severity: str | None,
    min_severity_rank: int | None,
    only_expected_severity: str | None,
    only_mismatches: bool,
) -> dict[str, Any]:
    """Assemble the final dispatch state for report()."""
    return {
        "only_mismatches": only_mismatches,
        "payload": payload,
        "summary": context["summary"],
        "filtered_summary": general_state["filtered_summary"],
        "mutations": general_state["mutations"],
        "pass_results": pass_results,
        "pass_support": general_state["pass_support"],
        "requested_validation_mode": context["requested_validation_mode"],
        "effective_validation_mode": context["effective_validation_mode"],
        "degraded_validation": context["degraded_validation"],
        "degraded_passes": general_state["degraded_passes"],
        "degradation_roles": general_state["degradation_roles"],
        "failed_gates": context["failed_gates"],
        "gate_evaluation": context["gate_evaluation"],
        "gate_requested": context["gate_requested"],
        "gate_results": context["gate_results"],
        "gate_failure_summary": context["gate_failure_summary"],
        "gate_failure_priority": context["gate_failure_priority"],
        "gate_failure_severity_priority": context["gate_failure_severity_priority"],
        "validation_policy": context["validation_policy"],
        "resolved_only_pass": context["resolved_only_pass"],
        "resolved_only_pass_failure": context["resolved_only_pass_failure"],
        "only_status": only_status,
        "only_degraded": only_degraded,
        "only_failed_gates": only_failed_gates,
        "only_risky_passes": only_risky_passes,
        "only_structural_risk": only_structural_risk,
        "only_symbolic_risk": only_symbolic_risk,
        "only_uncovered_passes": only_uncovered_passes,
        "only_covered_passes": only_covered_passes,
        "only_clean_passes": only_clean_passes,
        "output": output,
        "summary_only": summary_only,
        "require_results": require_results,
        "min_severity": min_severity,
        "min_severity_rank": min_severity_rank,
        "only_expected_severity": only_expected_severity,
        "only_pass": only_pass,
        "only_pass_failure": only_pass_failure,
        "selected_risk_pass_names": general_state["selected_risk_pass_names"],
        "symbolic_state": general_state["symbolic_state"],
    }
