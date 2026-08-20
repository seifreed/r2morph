from r2morph.devirtualization.iterative_simplifier import IterativeSimplifier
from tests.utils.assertions import expect

_EXPECTED_LEN_OPTIMIZED_CHECKPOINTS_5 = 5


def test_iterative_simplifier_optimize_trims_checkpoints():
    simplifier = IterativeSimplifier(binary=object())
    context = {"checkpoints": [1, 2, 3, 4, 5, 6]}

    optimized = simplifier._optimize_result(context)
    expect(not (optimized["optimization_applied"] is not True))
    expect(len(optimized["checkpoints"]) == _EXPECTED_LEN_OPTIMIZED_CHECKPOINTS_5)


def test_iterative_simplifier_rollback_without_checkpoints():
    simplifier = IterativeSimplifier(binary=object())
    expect(not (simplifier.rollback_to_checkpoint() is not False))
