"""
Dataclasses that replace the 20-57 parameter signatures in CLI report functions.

These context objects group related parameters into cohesive units,
following Clean Code principles for function argument lists.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ValidationState:
    """Validation mode and degradation context."""

    requested_validation_mode: str | None = None
    effective_validation_mode: str | None = None
    degraded_validation: bool = False
    degraded_passes: list[dict[str, Any]] = field(default_factory=list)
    degradation_roles: dict[str, int] = field(default_factory=dict)
    validation_policy: dict[str, Any] | None = None


@dataclass
class GateState:
    """Gate evaluation results and failure summaries."""

    failed_gates: bool = False
    gate_evaluation: dict[str, Any] = field(default_factory=dict)
    gate_requested: dict[str, Any] = field(default_factory=dict)
    gate_results: dict[str, Any] = field(default_factory=dict)
    gate_failure_summary: dict[str, Any] = field(default_factory=dict)
    gate_failure_priority: list[dict[str, Any]] = field(default_factory=list)
    gate_failure_severity_priority: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class FilterFlags:
    """Boolean flags controlling which report views to show."""

    only_mismatches: bool = False
    only_status: str | None = None
    only_degraded: bool = False
    only_failed_gates: bool = False
    only_risky_passes: bool = False
    only_structural_risk: bool = False
    only_symbolic_risk: bool = False
    only_uncovered_passes: bool = False
    only_covered_passes: bool = False
    only_clean_passes: bool = False
    only_pass: str | None = None
    only_pass_failure: str | None = None
    only_expected_severity: str | None = None


@dataclass
class SeverityFilter:
    """Severity threshold for report filtering."""

    min_severity: str | None = None
    min_severity_rank: int | None = None
    resolved_only_pass: str | None = None
    resolved_only_pass_failure: str | None = None
    selected_risk_pass_names: set[str] = field(default_factory=set)


@dataclass
class OutputConfig:
    """Report output configuration."""

    output: Path | None = None
    summary_only: bool = False
    require_results: bool = False


@dataclass
class ReportPayload:
    """Core report data passed between report functions."""

    payload: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    filtered_summary: dict[str, Any] = field(default_factory=dict)
    mutations: list[dict[str, Any]] = field(default_factory=list)
    pass_results: dict[str, Any] = field(default_factory=dict)
    pass_support: dict[str, Any] = field(default_factory=dict)
    symbolic_state: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportFlowContext:
    """Complete context for report flow dispatch.

    Replaces the 41-57 parameter signatures in _dispatch_report_flow,
    _execute_general_report_flow, and _execute_only_mismatches_report_flow.
    """

    data: ReportPayload
    validation: ValidationState
    gates: GateState
    filters: FilterFlags
    severity: SeverityFilter
    output: OutputConfig
