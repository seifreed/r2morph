from r2morph.analysis.symbolic.state_manager_models import StateMetrics, StateSchedulingStrategy
from tests.utils.assertions import expect

_EXPECTED_METRICS_COVERAGE_NEW_BLOCKS_2 = 2
_EXPECTED_METRICS_DEPTH_3 = 3


def test_state_manager_models_contract() -> None:
    expect(StateSchedulingStrategy.PRIORITY_BASED.value == "priority_based")
    metrics = StateMetrics(depth=3, coverage_new_blocks=2)
    expect(metrics.depth == _EXPECTED_METRICS_DEPTH_3)
    expect(metrics.coverage_new_blocks == _EXPECTED_METRICS_COVERAGE_NEW_BLOCKS_2)
