from r2morph.devirtualization.iterative_simplifier_models import (
    SimplificationMetrics,
    SimplificationPhase,
    SimplificationResult,
    SimplificationStrategy,
)


def test_iterative_simplifier_models_expose_expected_contract() -> None:
    metrics = SimplificationMetrics(iteration=2, simplified_expressions=4)
    result = SimplificationResult(
        success=True,
        strategy_used=SimplificationStrategy.ADAPTIVE,
        metrics=metrics,
    )

    assert SimplificationPhase.OPTIMIZATION.value == "optimization"
    assert result.metrics.iteration == 2
    assert result.metrics.simplified_expressions == 4
    assert result.strategy_used is SimplificationStrategy.ADAPTIVE
