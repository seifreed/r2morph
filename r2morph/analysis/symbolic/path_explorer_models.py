"""Shared model types for symbolic path exploration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ExplorationStrategy(Enum):
    """Path exploration strategies for different analysis goals."""

    BFS = "breadth_first"
    DFS = "depth_first"
    GUIDED = "guided"
    VM_HANDLER = "vm_handler"
    OPAQUE_PREDICATE = "opaque_predicate"


@dataclass
class ExplorationResult:
    """Result of path exploration."""

    paths_explored: int = 0
    vm_handlers_found: int = 0
    opaque_predicates_found: int = 0
    interesting_paths: list[Any] = field(default_factory=list)
    execution_time: float = 0.0
    constraints_collected: list[Any] = field(default_factory=list)
    coverage_info: dict[str, Any] = field(default_factory=dict)
