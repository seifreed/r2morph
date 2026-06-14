"""Data models for mutation fuzzer inputs and results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FuzzConfig:
    """Configuration for fuzzer."""

    num_tests: int = 100
    timeout: int = 5
    seed: int | None = None
    input_types: list[str] = field(default_factory=lambda: ["random", "ascii", "structured"])
    max_input_size: int = 4096
    min_input_size: int = 0
    crash_on_error: bool = False
    save_failing_cases: bool = True
    output_dir: str = "fuzz_results"


@dataclass
class FuzzTestCase:
    """A single fuzz test case."""

    test_id: str
    input_data: bytes
    input_type: str
    args: list[str]
    env: dict[str, str]
    description: str


@dataclass
class FuzzResult:
    """Result of a single fuzz test."""

    test_id: str
    passed: bool
    original_exit_code: int
    mutated_exit_code: int
    original_output_hash: str
    mutated_output_hash: str
    original_error: str | None
    mutated_error: str | None
    execution_time_ms: float
    crash: bool
    timeout: bool
    mutation_count: int
    mutation_names: list[str]


@dataclass
class FuzzCampaignResult:
    """Result of a complete fuzz campaign."""

    total_tests: int
    passed: int
    failed: int
    crashes: int
    timeouts: int
    results: list[FuzzResult]
    seed: int
    config: FuzzConfig
    start_time: str
    end_time: str
    duration_seconds: float

    @property
    def success_rate(self) -> float:
        return (self.passed / self.total_tests * 100) if self.total_tests > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "crashes": self.crashes,
            "timeouts": self.timeouts,
            "success_rate": f"{self.success_rate:.2f}%",
            "seed": self.seed,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "results": [asdict(r) for r in self.results],
        }
