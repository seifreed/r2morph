"""A real GateFailureReporterProtocol double that records calls."""

from __future__ import annotations

from typing import Any


class RecordingGateFailureReporter:
    """Records every call and returns fixed sentinels (no real logic)."""

    SUMMARY: dict[str, Any] = {"sentinel": "summary"}
    PRIORITY: list[dict[str, Any]] = [{"sentinel": "priority"}]
    SEVERITY_PRIORITY: list[dict[str, Any]] = [{"sentinel": "severity"}]

    def __init__(self) -> None:
        self.summarize_calls: list[dict[str, Any]] = []
        self.priority_calls: list[dict[str, Any] | None] = []
        self.severity_priority_calls: list[dict[str, Any] | None] = []

    def summarize_gate_failures(self, gate_evaluation: dict[str, Any]) -> dict[str, Any]:
        self.summarize_calls.append(gate_evaluation)
        return dict(self.SUMMARY)

    def build_gate_failure_priority(self, gate_failures: dict[str, Any] | None) -> list[dict[str, Any]]:
        self.priority_calls.append(gate_failures)
        return [dict(row) for row in self.PRIORITY]

    def build_gate_failure_severity_priority(self, gate_failures: dict[str, Any] | None) -> list[dict[str, Any]]:
        self.severity_priority_calls.append(gate_failures)
        return [dict(row) for row in self.SEVERITY_PRIORITY]
