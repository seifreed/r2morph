"""Planning models and dependency resolution for parallel mutation execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

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
        pass_names = {p.name for p in passes}

        for p in passes:
            if p.name not in self.dependencies:
                self.dependencies[p.name] = PassDependency(p.name, requires=[], conflicts=[])

        stages: list[list[str]] = []
        scheduled: set[str] = set()

        while len(scheduled) < len(pass_names):
            stage: list[str] = []

            for pass_name in pass_names:
                if pass_name in scheduled:
                    continue

                dep = self.dependencies.get(pass_name, PassDependency(pass_name))
                if any(req not in scheduled for req in dep.requires):
                    continue
                if any(conflict in scheduled for conflict in dep.conflicts):
                    continue

                stage.append(pass_name)

            if not stage:
                remaining = pass_names - scheduled
                stage = list(remaining)

            scheduled.update(stage)
            stages.append(stage)

        return ExecutionPlan(passes=passes, dependencies=self.dependencies, stages=stages)

    def check_conflicts(self, passes: list[MutationPassProtocol]) -> list[tuple[str, str]]:
        conflicts: list[tuple[str, str]] = []
        pass_names = [p.name for p in passes]

        for i, name1 in enumerate(pass_names):
            for name2 in pass_names[i + 1 :]:
                dep1 = self.dependencies.get(name1, PassDependency(name1))
                dep2 = self.dependencies.get(name2, PassDependency(name2))

                if name2 in dep1.conflicts or name1 in dep2.conflicts:
                    conflicts.append((name1, name2))

        return conflicts


__all__ = [
    "DependencyResolver",
    "ExecutionPlan",
    "PassDependency",
    "PassResult",
    "PassStatus",
]
