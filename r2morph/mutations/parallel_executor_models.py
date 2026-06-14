"""Data models for parallel mutation execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from r2morph.mutations.base import MutationPass, MutationRecord


@dataclass
class MutationTask:
    """A mutation task for parallel execution."""

    pass_name: str
    pass_instance: MutationPass
    function_addresses: list[int] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class MutationResult:
    """Result of a mutation task."""

    success: bool = True
    mutations_applied: int = 0
    records: list[MutationRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParallelStats:
    """Statistics from parallel execution."""

    total_time: float = 0.0
    worker_count: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_mutations: int = 0
    speedup_factor: float = 1.0
