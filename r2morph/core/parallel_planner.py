"""Planning models and dependency resolution for parallel mutation execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from r2morph.core.parallel_planner_helpers import build_conflict_pairs, build_execution_stages
from r2morph.protocols import MutationPassProtocol


class PassStatus(Enum):
    """Status of a mutation pass."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class PassResult:
    """Result of executing a mutation pass."""

    pass_name: str
    status: PassStatus
    result: dict[str, Any] | None = None
    error: str | None = None
    duration_seconds: float = 0.0
    mutations_applied: int = 0
    checkpoint_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pass_name": self.pass_name,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
            "mutations_applied": self.mutations_applied,
            "checkpoint_path": str(self.checkpoint_path) if self.checkpoint_path else None,
        }


@dataclass
class PassDependency:
    """Declares dependencies between mutation passes."""

    pass_name: str
    requires: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    optional: bool = False


@dataclass
class ExecutionPlan:
    """Execution plan for parallel mutations."""

    passes: list[MutationPassProtocol]
    dependencies: dict[str, PassDependency] = field(default_factory=dict)
    stages: list[list[str]] = field(default_factory=list)

    def get_stage(self, pass_name: str) -> int:
        """Get the stage number for a pass."""
        for i, stage in enumerate(self.stages):
            if pass_name in stage:
                return i
        return -1


class DependencyResolver:
    """Resolves dependencies between mutation passes."""

    KNOWN_DEPENDENCIES: dict[str, PassDependency] = {
        "nop": PassDependency("nop", requires=[], conflicts=[]),
        "substitute": PassDependency("substitute", requires=[], conflicts=[]),
        "register": PassDependency("register", requires=[], conflicts=["substitute"]),
        "block": PassDependency("block", requires=[], conflicts=["nop", "substitute", "register"]),
        "cff": PassDependency("cff", requires=[], conflicts=["block", "nop"]),
        "dead-code": PassDependency("dead-code", requires=[], conflicts=[]),
        "opaque": PassDependency("opaque", requires=[], conflicts=["cff"]),
    }

    def __init__(self, custom_dependencies: dict[str, PassDependency] | None = None) -> None:
        self.dependencies = dict(self.KNOWN_DEPENDENCIES)
        if custom_dependencies:
            self.dependencies.update(custom_dependencies)

    def resolve(self, passes: list[MutationPassProtocol]) -> ExecutionPlan:
        for p in passes:
            if p.name not in self.dependencies:
                self.dependencies[p.name] = PassDependency(p.name, requires=[], conflicts=[])
        stages = build_execution_stages(passes, self.dependencies)
        return ExecutionPlan(passes=passes, dependencies=self.dependencies, stages=stages)

    def check_conflicts(self, passes: list[MutationPassProtocol]) -> list[tuple[str, str]]:
        return build_conflict_pairs(passes, self.dependencies)


__all__ = [
    "DependencyResolver",
    "ExecutionPlan",
    "PassDependency",
    "PassResult",
    "PassStatus",
]
