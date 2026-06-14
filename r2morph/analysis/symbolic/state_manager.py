"""
State management for symbolic execution.

This module provides efficient management of symbolic execution states,
including state pruning, merging, and scheduling strategies optimized
for analyzing obfuscated binaries.
"""

import heapq
import logging
from typing import Any

from r2morph.analysis.symbolic.state_manager_models import StateMetrics, StateSchedulingStrategy
from r2morph.analysis.symbolic.state_manager_policies import (
    calculate_pruning_score,
    get_best_coverage_state,
    get_deepest_state,
    get_highest_priority_state,
    get_random_state,
    get_shallowest_state,
    merge_equivalent_states,
    merge_state_group,
    prune_states,
    remove_state,
    select_next_state,
    update_state_depth,
)

_angr: Any = None
try:
    import angr as _angr_mod

    ANGR_AVAILABLE = True
    _angr = _angr_mod
except ImportError:
    ANGR_AVAILABLE = False

angr = _angr

logger = logging.getLogger(__name__)


class StateManager:
    """
    Advanced state manager for symbolic execution.

    Provides intelligent state management including:
    - State prioritization and scheduling
    - Memory-efficient state storage
    - State merging for equivalent states
    - Adaptive state pruning
    """

    def __init__(
        self,
        max_states: int = 100,
        max_depth: int = 1000,
        scheduling_strategy: StateSchedulingStrategy = StateSchedulingStrategy.PRIORITY_BASED,
    ):
        """
        Initialize state manager.

        Args:
            max_states: Maximum number of active states
            max_depth: Maximum exploration depth
            scheduling_strategy: State scheduling strategy
        """
        if not ANGR_AVAILABLE:
            logger.warning("angr not available, state management will be limited")

        self.max_states = max_states
        self.max_depth = max_depth
        self.scheduling_strategy = scheduling_strategy

        # State storage
        self.active_states: dict[int, Any] = {}
        self.state_metrics: dict[int, StateMetrics] = {}
        self.state_priority_queue: list[tuple] = []  # (priority, state_id)

        # Coverage tracking
        self.global_coverage: set[int] = set()
        self.state_coverage: dict[int, set[int]] = {}

        # Performance metrics
        self.states_created = 0
        self.states_pruned = 0
        self.states_merged = 0

    def add_state(self, state: Any, priority: float = 0.0) -> int:
        """
        Add a new state to management.

        Args:
            state: Symbolic state
            priority: Initial priority score

        Returns:
            State ID
        """
        if not ANGR_AVAILABLE:
            return -1

        state_id = self.states_created
        self.states_created += 1

        # Store state and initialize metrics
        self.active_states[state_id] = state
        self.state_metrics[state_id] = StateMetrics(depth=self._get_state_depth(state), priority_score=priority)
        self.state_coverage[state_id] = set()

        # Add to priority queue
        heapq.heappush(self.state_priority_queue, (-priority, state_id))

        # Enforce state limit
        if len(self.active_states) > self.max_states:
            self._prune_states()

        logger.debug(f"Added state {state_id} with priority {priority}")
        return state_id

    def get_next_state(self) -> tuple[int, Any] | None:
        return select_next_state(self)

    def get_active_states(self) -> list[Any]:
        """Return a list of currently active states."""
        return list(self.active_states.values())

    def _get_highest_priority_state(self) -> tuple[int, Any] | None:
        return get_highest_priority_state(self)

    def _get_best_coverage_state(self) -> tuple[int, Any] | None:
        return get_best_coverage_state(self)

    def _get_deepest_state(self) -> tuple[int, Any] | None:
        return get_deepest_state(self)

    def _get_shallowest_state(self) -> tuple[int, Any] | None:
        return get_shallowest_state(self)

    def _get_random_state(self) -> tuple[int, Any] | None:
        return get_random_state(self)

    def update_state_coverage(self, state_id: int, new_blocks: set[int]) -> None:
        """
        Update coverage information for a state.

        Args:
            state_id: State identifier
            new_blocks: Set of newly covered basic blocks
        """
        if state_id not in self.state_coverage:
            return

        # Track new blocks for this state
        state_coverage = self.state_coverage[state_id]
        truly_new_blocks = new_blocks - self.global_coverage

        # Update global and state coverage
        self.global_coverage.update(new_blocks)
        state_coverage.update(new_blocks)

        # Update metrics
        if state_id in self.state_metrics:
            self.state_metrics[state_id].coverage_new_blocks = len(truly_new_blocks)

        logger.debug(f"State {state_id} found {len(truly_new_blocks)} new blocks")

    def update_state_priority(self, state_id: int, new_priority: float) -> None:
        """
        Update priority of a state.

        Args:
            state_id: State identifier
            new_priority: New priority score
        """
        if state_id in self.state_metrics:
            self.state_metrics[state_id].priority_score = new_priority
            # Re-add to priority queue
            heapq.heappush(self.state_priority_queue, (-new_priority, state_id))

    def _prune_states(self) -> None:
        prune_states(self)

    def _calculate_pruning_score(self, metrics: StateMetrics) -> float:
        return calculate_pruning_score(self, metrics)

    def _remove_state(self, state_id: int) -> None:
        remove_state(self, state_id)

    def _get_state_depth(self, state: Any) -> int:
        return update_state_depth(state)

    def merge_equivalent_states(self) -> int:
        if not ANGR_AVAILABLE:
            return 0

        return merge_equivalent_states(self)

    def _try_merge_states_at_pc(self, state_ids: list[int]) -> int:
        return merge_state_group(self, state_ids)

    def get_statistics(self) -> dict[str, Any]:
        """Get state management statistics."""
        return {
            "active_states": len(self.active_states),
            "total_coverage": len(self.global_coverage),
            "states_created": self.states_created,
            "states_pruned": self.states_pruned,
            "states_merged": self.states_merged,
            "max_depth": max((m.depth for m in self.state_metrics.values()), default=0),
            "avg_priority": sum(m.priority_score for m in self.state_metrics.values())
            / max(len(self.state_metrics), 1),
        }

    def cleanup(self) -> None:
        """Clean up state manager resources."""
        self.active_states.clear()
        self.state_metrics.clear()
        self.state_coverage.clear()
        self.state_priority_queue.clear()
        self.global_coverage.clear()
