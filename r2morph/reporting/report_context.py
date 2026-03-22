"""
Dataclasses that replace the 20-57 parameter signatures in CLI report functions.

These context objects group related parameters into cohesive units,
following Clean Code principles for function argument lists.
"""

from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Iterator


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
class ReportViews:
    """Typed return value for build_report_views, replacing dict[str, Any]."""

    general_passes: list[dict[str, Any]] = field(default_factory=list)
    general_pass_rows: list[dict[str, Any]] = field(default_factory=list)
    general_summary: dict[str, Any] = field(default_factory=dict)
    general_summary_rows: list[dict[str, Any]] = field(default_factory=list)
    general_renderer_state: dict[str, Any] = field(default_factory=dict)
    general_triage_rows: list[dict[str, Any]] = field(default_factory=list)
    general_filter_views: dict[str, list[str]] = field(default_factory=dict)
    general_symbolic: dict[str, Any] = field(default_factory=dict)
    general_gates: dict[str, Any] = field(default_factory=dict)
    general_degradation: dict[str, Any] = field(default_factory=dict)
    general_discards: dict[str, Any] = field(default_factory=dict)
    passes: dict[str, list[str]] = field(default_factory=dict)
    triage_priority: list[dict[str, Any]] = field(default_factory=list)
    only_pass: dict[str, dict[str, Any]] = field(default_factory=dict)
    pass_filter_views: dict[str, list[str]] = field(default_factory=dict)
    mismatch_priority: list[dict[str, Any]] = field(default_factory=list)
    mismatch_map: dict[str, dict[str, Any]] = field(default_factory=dict)
    mismatch_view: list[dict[str, Any]] = field(default_factory=list)
    only_mismatches: dict[str, Any] = field(default_factory=dict)
    failed_gates: list[dict[str, Any]] = field(default_factory=list)
    only_failed_gates: dict[str, Any] = field(default_factory=dict)
    validation_adjustments: dict[str, Any] = field(default_factory=dict)
    discarded_view: dict[str, Any] = field(default_factory=dict)

    # -- dict-like API for backward compatibility --

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key) and key in {f.name for f in fields(self)}

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-compatible .get() for backward compatibility."""
        try:
            return getattr(self, key)
        except AttributeError:
            return default

    def keys(self) -> list[str]:
        """Return field names, enabling dict(report_views)."""
        return [f.name for f in fields(self)]

    def values(self) -> list[Any]:
        """Return field values."""
        return [getattr(self, f.name) for f in fields(self)]

    def items(self) -> list[tuple[str, Any]]:
        """Return (name, value) pairs."""
        return [(f.name, getattr(self, f.name)) for f in fields(self)]

    def __iter__(self) -> Iterator[str]:
        """Iterate over field names so dict(obj) works."""
        return iter(self.keys())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for backward compatibility."""
        return asdict(self)


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
