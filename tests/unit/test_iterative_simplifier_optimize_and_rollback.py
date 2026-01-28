from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier


def test_iterative_simplifier_optimize_trims_checkpoints():
    simplifier = IterativeSimplifier(binary=object())
    context = {"checkpoints": [1, 2, 3, 4, 5, 6]}

    optimized = simplifier._optimize_result(context)
    assert optimized["optimization_applied"] is True
    assert len(optimized["checkpoints"]) == 5


def test_iterative_simplifier_rollback_without_checkpoints():
    simplifier = IterativeSimplifier(binary=object())
    assert simplifier.rollback_to_checkpoint() is False
