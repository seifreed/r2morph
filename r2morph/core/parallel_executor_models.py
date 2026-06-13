"""Pure models for parallel mutation execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaskStatus(Enum):
    """Status of a mutation task."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ResolutionStrategy(Enum):
    """Strategy for conflict resolution."""

    SKIP = "skip"
    REORDER = "reorder"
    MERGE = "merge"
    ABORT = "abort"


@dataclass
class MutationTask:
    """Represents a mutation task for parallel execution."""

    task_id: int
    function_address: int
    function_name: str = ""
    passes: list[str] = field(default_factory=list)
    dependencies: list[int] = field(default_factory=list)
    priority: int = 0
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: str | None = None
    execution_time: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.task_id)

    def is_ready(self, completed: set[int]) -> bool:
        """Check if task is ready to run."""
        return all(dep in completed for dep in self.dependencies)


@dataclass
class MutationResult:
    """Result of a mutation task."""

    task_id: int
    function_address: int
    function_name: str
    success: bool
    mutations_applied: list[dict[str, Any]] = field(default_factory=list)
    bytes_modified: int = 0
    execution_time: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "function_address": f"0x{self.function_address:x}",
            "function_name": self.function_name,
            "success": self.success,
            "mutations_applied": self.mutations_applied,
            "bytes_modified": self.bytes_modified,
            "execution_time": self.execution_time,
            "error": self.error,
            "metadata": self.metadata,
        }


__all__ = ["MutationResult", "MutationTask", "ResolutionStrategy", "TaskStatus"]
