from __future__ import annotations

import pytest

from r2morph.devirtualization.iterative_simplifier import (
    IterativeSimplifier,
    SimplificationStrategy,
)
from tests.utils.assertions import expect

_EXPECTED_CHECKPOINT_ITERATION_3 = 3
_EXPECTED_LEN_OPTIMIZED_CHECKPOINTS_5 = 5
_EXPECTED_SIMPLIFIER_CALCULATE_COMPLEXITY_CONTEXT_25_0 = 25.0
_EXPECTED_SIMPLIFIER_METRICS_DEVIRTUALIZED_HANDLERS_3 = 3


class DummyVM:
    def __init__(self, handlers: list[int]):
        self.handlers = handlers


def test_iterative_simplifier_complexity_and_strategy_adjustment() -> None:
    simplifier = IterativeSimplifier()
    context = {
        "functions": [0x10, 0x20],
        "obfuscation_patterns": ["dispatcher"],
        "mba_expressions": ["a+b", "x^y"],
        "vm_dispatchers": [0x100, 0x200],
    }

    expect(simplifier._calculate_complexity(context) == _EXPECTED_SIMPLIFIER_CALCULATE_COMPLEXITY_CONTEXT_25_0)

    expect(simplifier.strategy == SimplificationStrategy.ADAPTIVE)
    initial_threshold = simplifier.convergence_threshold
    simplifier._adjust_strategy(0.06, 1)
    expect(simplifier.convergence_threshold == pytest.approx(initial_threshold * 0.8))

    simplifier._adjust_strategy(0.0, 2)
    expect(simplifier.convergence_threshold == pytest.approx(initial_threshold * 0.8 * 1.2))


def test_iterative_simplifier_checkpoint_metrics_and_validation() -> None:
    simplifier = IterativeSimplifier()
    simplifier.metrics.iteration = 3

    context = {
        "functions": [0x10, 0x20],
        "initial_complexity": 10,
        "checkpoints": list(range(7)),
        "mba_results": [object()],
        "vm_results": [DummyVM([1, 2, 3])],
    }

    checkpoint = simplifier._create_checkpoint(context)
    expect(checkpoint["iteration"] == _EXPECTED_CHECKPOINT_ITERATION_3)
    expect(checkpoint["context"] == context)
    expect(checkpoint["context"] is not context)

    simplifier._update_metrics(context)
    expect(not (simplifier.metrics.simplified_expressions < 1))
    expect(simplifier.metrics.devirtualized_handlers == _EXPECTED_SIMPLIFIER_METRICS_DEVIRTUALIZED_HANDLERS_3)
    expected_reduction = (10 - simplifier._calculate_complexity(context)) / 10
    expect(simplifier.metrics.complexity_reduction == pytest.approx(expected_reduction))

    optimized = simplifier._optimize_result(context)
    expect(not (optimized["optimization_applied"] is not True))
    expect(len(optimized["checkpoints"]) == _EXPECTED_LEN_OPTIMIZED_CHECKPOINTS_5)

    simplifier.metrics.complexity_reduction = 0.0
    validation = simplifier._validate_result({"errors": ["oops"]})
    expect(not (validation["valid"] is not True))
    expect(validation["warnings"])
