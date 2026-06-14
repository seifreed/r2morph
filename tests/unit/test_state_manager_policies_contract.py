from types import SimpleNamespace

from r2morph.analysis.symbolic.state_manager_models import StateMetrics, StateSchedulingStrategy
from r2morph.analysis.symbolic.state_manager_policies import (
    calculate_pruning_score,
    get_best_coverage_state,
    merge_equivalent_states,
    prune_states,
    select_next_state,
)


def test_state_manager_policies_contract() -> None:
    manager = SimpleNamespace()
    manager.scheduling_strategy = StateSchedulingStrategy.PRIORITY_BASED
    manager.state_priority_queue = [(-2.0, 2), (-1.0, 1)]
    manager.active_states = {1: object(), 2: object()}
    manager.state_metrics = {
        1: StateMetrics(depth=1, coverage_new_blocks=5, priority_score=1.0),
        2: StateMetrics(depth=4, coverage_new_blocks=0, priority_score=2.0),
    }
    manager.max_states = 1
    manager.max_depth = 10
    manager.state_coverage = {1: set(), 2: set()}
    manager.states_pruned = 0
    manager.states_merged = 0

    assert select_next_state(manager)[0] == 2

    manager.scheduling_strategy = StateSchedulingStrategy.COVERAGE_GUIDED
    assert get_best_coverage_state(manager)[0] == 1

    assert calculate_pruning_score(manager, manager.state_metrics[1]) > calculate_pruning_score(
        manager, manager.state_metrics[2]
    )

    prune_states(manager)
    assert len(manager.active_states) == 1
    assert manager.states_pruned == 1

    manager.active_states = {10: SimpleNamespace(addr=0x1000), 11: SimpleNamespace(addr=0x1000)}
    manager.state_metrics = {
        10: StateMetrics(depth=1, coverage_new_blocks=1, priority_score=1.0),
        11: StateMetrics(depth=2, coverage_new_blocks=0, priority_score=0.5),
    }
    manager.state_coverage = {10: set(), 11: set()}
    manager.states_merged = 0

    assert merge_equivalent_states(manager) == 1
    assert len(manager.active_states) == 1
    assert manager.states_merged == 1
