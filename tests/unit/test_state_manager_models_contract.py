from r2morph.analysis.symbolic.state_manager_models import StateMetrics, StateSchedulingStrategy


def test_state_manager_models_contract() -> None:
    assert StateSchedulingStrategy.PRIORITY_BASED.value == "priority_based"
    metrics = StateMetrics(depth=3, coverage_new_blocks=2)
    assert metrics.depth == 3
    assert metrics.coverage_new_blocks == 2
