"""State selection and pruning helpers for symbolic execution."""

from __future__ import annotations

import heapq
import logging
import random
import time
from typing import Any

from r2morph.analysis.symbolic.state_manager_models import StateMetrics, StateSchedulingStrategy

logger = logging.getLogger(__name__)


def select_next_state(manager: Any) -> tuple[int, Any] | None:
    """Select the next state based on the configured scheduling strategy."""
    if not manager.state_priority_queue:
        return None

    if manager.scheduling_strategy == StateSchedulingStrategy.PRIORITY_BASED:
        return get_highest_priority_state(manager)
    if manager.scheduling_strategy == StateSchedulingStrategy.COVERAGE_GUIDED:
        return get_best_coverage_state(manager)
    if manager.scheduling_strategy == StateSchedulingStrategy.DEPTH_FIRST:
        return get_deepest_state(manager)
    if manager.scheduling_strategy == StateSchedulingStrategy.BREADTH_FIRST:
        return get_shallowest_state(manager)
    return get_random_state(manager)


def get_highest_priority_state(manager: Any) -> tuple[int, Any] | None:
    """Get the state with the highest priority."""
    while manager.state_priority_queue:
        _, state_id = heapq.heappop(manager.state_priority_queue)
        if state_id in manager.active_states:
            return state_id, manager.active_states[state_id]
    return None


def get_best_coverage_state(manager: Any) -> tuple[int, Any] | None:
    """Get the state most likely to increase coverage."""
    best_state_id = None
    best_score = -1.0

    for state_id in manager.active_states:
        metrics = manager.state_metrics[state_id]
        score = metrics.coverage_new_blocks - (metrics.depth * 0.1)

        if score > best_score:
            best_score = score
            best_state_id = state_id

    if best_state_id is not None:
        return best_state_id, manager.active_states[best_state_id]
    return None


def get_deepest_state(manager: Any) -> tuple[int, Any] | None:
    """Get the deepest active state."""
    deepest_id = None
    max_depth = -1

    for state_id in manager.active_states:
        depth = manager.state_metrics[state_id].depth
        if depth > max_depth:
            max_depth = depth
            deepest_id = state_id

    if deepest_id is not None:
        return deepest_id, manager.active_states[deepest_id]
    return None


def get_shallowest_state(manager: Any) -> tuple[int, Any] | None:
    """Get the shallowest active state."""
    shallowest_id = None
    min_depth = float("inf")

    for state_id in manager.active_states:
        depth = manager.state_metrics[state_id].depth
        if depth < min_depth:
            min_depth = depth
            shallowest_id = state_id

    if shallowest_id is not None:
        return shallowest_id, manager.active_states[shallowest_id]
    return None


def get_random_state(manager: Any) -> tuple[int, Any] | None:
    """Get a random active state."""
    if manager.active_states:
        state_id = random.choice(list(manager.active_states.keys()))
        return state_id, manager.active_states[state_id]
    return None


def update_state_depth(state: Any) -> int:
    """Get the exploration depth of a state."""
    if hasattr(state, "history"):
        return int(state.history.depth)
    return 0


def calculate_pruning_score(manager: Any, metrics: StateMetrics) -> float:
    """
    Calculate a pruning score for a state.

    Lower scores are more likely to be pruned.
    """
    score = 0.0
    score += metrics.coverage_new_blocks * 10.0
    score += metrics.vm_likelihood_score * 5.0

    if metrics.depth > manager.max_depth * 0.8:
        score -= (metrics.depth - manager.max_depth * 0.8) * 2.0

    score -= metrics.constraint_complexity * 0.1
    age = time.time() - metrics.last_access_time
    score -= age * 0.01

    return score


def prune_states(manager: Any) -> None:
    """Prune the least promising states."""
    if len(manager.active_states) <= manager.max_states:
        return

    states_to_evaluate: list[tuple[float, int]] = []
    for state_id, metrics in manager.state_metrics.items():
        if state_id in manager.active_states:
            states_to_evaluate.append((calculate_pruning_score(manager, metrics), state_id))

    states_to_evaluate.sort()

    states_to_prune = len(manager.active_states) - manager.max_states
    for index in range(states_to_prune):
        if index < len(states_to_evaluate):
            _, state_id = states_to_evaluate[index]
            remove_state(manager, state_id)
            manager.states_pruned += 1

    logger.debug(f"Pruned {states_to_prune} states")


def remove_state(manager: Any, state_id: int) -> None:
    """Remove a state from the manager."""
    if state_id in manager.active_states:
        del manager.active_states[state_id]
    if state_id in manager.state_metrics:
        del manager.state_metrics[state_id]
    if state_id in manager.state_coverage:
        del manager.state_coverage[state_id]


def merge_equivalent_states(manager: Any) -> int:
    """
    Merge states that are equivalent at the same program point.

    Returns the number of removed states.
    """
    pc_groups: dict[int, list[int]] = {}

    for state_id, state in manager.active_states.items():
        try:
            pc = state.addr
        except Exception as exc:
            logger.debug(f"Failed to get PC for state {state_id}: {exc}")
            continue

        pc_groups.setdefault(pc, []).append(state_id)

    merged_count = 0
    for state_ids in pc_groups.values():
        if len(state_ids) > 1:
            merged_count += merge_state_group(manager, state_ids)

    manager.states_merged += merged_count
    return merged_count


def merge_state_group(manager: Any, state_ids: list[int]) -> int:
    """Keep the best state from a group and drop the rest."""
    if len(state_ids) <= 1:
        return 0

    best_state_id = state_ids[0]
    best_score = calculate_pruning_score(manager, manager.state_metrics[best_state_id])

    for state_id in state_ids[1:]:
        score = calculate_pruning_score(manager, manager.state_metrics[state_id])
        if score > best_score:
            best_score = score
            best_state_id = state_id

    merged_count = 0
    for state_id in state_ids:
        if state_id != best_state_id:
            remove_state(manager, state_id)
            merged_count += 1

    return merged_count
