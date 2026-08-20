from r2morph.devirtualization.iterative_simplifier_models import (
    SimplificationMetrics,
    SimplificationPhase,
    SimplificationResult,
    SimplificationStrategy,
)
from tests.utils.assertions import expect

_EXPECTED_RESULT_METRICS_ITERATION_2 = 2
_EXPECTED_RESULT_METRICS_SIMPLIFIED_EXPRESSIONS_4 = 4


def test_iterative_simplifier_models_expose_expected_contract() -> None:
    metrics = SimplificationMetrics(iteration=2, simplified_expressions=4)
    result = SimplificationResult(
        success=True,
        strategy_used=SimplificationStrategy.ADAPTIVE,
        metrics=metrics,
    )

    expect(SimplificationPhase.OPTIMIZATION.value == "optimization")
    expect(result.metrics.iteration == _EXPECTED_RESULT_METRICS_ITERATION_2)
    expect(result.metrics.simplified_expressions == _EXPECTED_RESULT_METRICS_SIMPLIFIED_EXPRESSIONS_4)
    expect(not (result.strategy_used is not SimplificationStrategy.ADAPTIVE))
