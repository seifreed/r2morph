from __future__ import annotations

import pytest

from r2morph.devirtualization.iterative_simplifier import (
    IterativeSimplifier,
    SimplificationStrategy,
)


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

    assert simplifier._calculate_complexity(context) == 25.0

    assert simplifier.strategy == SimplificationStrategy.ADAPTIVE
    initial_threshold = simplifier.convergence_threshold
    simplifier._adjust_strategy(0.06, 1)
    assert simplifier.convergence_threshold == pytest.approx(initial_threshold * 0.8)

    simplifier._adjust_strategy(0.0, 2)
    assert simplifier.convergence_threshold == pytest.approx(initial_threshold * 0.8 * 1.2)


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
    assert checkpoint["iteration"] == 3
    assert checkpoint["context"] == context
    assert checkpoint["context"] is not context

    simplifier._update_metrics(context)
    assert simplifier.metrics.simplified_expressions >= 1
    assert simplifier.metrics.devirtualized_handlers == 3
    expected_reduction = (10 - simplifier._calculate_complexity(context)) / 10
    assert simplifier.metrics.complexity_reduction == pytest.approx(expected_reduction)

    optimized = simplifier._optimize_result(context)
    assert optimized["optimization_applied"] is True
    assert len(optimized["checkpoints"]) == 5

    simplifier.metrics.complexity_reduction = 0.0
    validation = simplifier._validate_result({"errors": ["oops"]})
    assert validation["valid"] is True
    assert validation["warnings"]
