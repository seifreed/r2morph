"""Pure data models for symbolic state management."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class StateSchedulingStrategy(Enum):
    """Strategies for scheduling state exploration."""

    RANDOM = "random"
    DEPTH_FIRST = "depth_first"
    BREADTH_FIRST = "breadth_first"
    COVERAGE_GUIDED = "coverage_guided"
    PRIORITY_BASED = "priority_based"


@dataclass
class StateMetrics:
    """Metrics for evaluating state quality."""

    depth: int = 0
    coverage_new_blocks: int = 0
    constraint_complexity: float = 0.0
    vm_likelihood_score: float = 0.0
    last_access_time: float = field(default_factory=time.time)
    priority_score: float = 0.0
