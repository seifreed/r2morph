"""Dataclasses for report builder context and filtered payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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
