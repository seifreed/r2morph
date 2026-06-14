"""Data models for performance regression testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PerformanceMetric:
    """Single performance metric measurement."""

    name: str
    value: float
    unit: str
    timestamp: str
    sample_size: int = 1


@dataclass
class PerformanceSnapshot:
    """Snapshot of performance at a point in time."""

    commit_hash: str
    timestamp: str
    metrics: dict[str, float]
    environment: dict[str, str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit_hash": self.commit_hash,
            "timestamp": self.timestamp,
            "metrics": self.metrics,
            "environment": self.environment,
            "metadata": self.metadata,
        }


@dataclass
class PerformanceRegression:
    """Detected performance regression."""

    metric_name: str
    baseline_value: float
    current_value: float
    threshold: float
    percentage_change: float
    severity: str  # "minor", "major", "critical"


@dataclass
class BenchmarkConfig:
    """Configuration for performance benchmarking."""

    warmup_runs: int = 3
    measured_runs: int = 10
    timeout_seconds: int = 300
    max_memory_mb: int = 1024
    regression_threshold_percent: float = 20.0
    critical_threshold_percent: float = 50.0
