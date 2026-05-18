"""Regression: IterativeSimplifier.simplify must not crash on a binary
with zero detectable complexity.

Before the fix, ``_calculate_complexity`` returning ``0.0`` made
``prev_complexity`` zero, and the convergence step computed
``(prev_complexity - current_complexity) / prev_complexity`` -> a
``ZeroDivisionError`` that the outer handler surfaced as a spurious
``success=False`` with a confusing "float division by zero" error. A
clean/trivial binary has nothing to simplify and must converge
successfully.

No mocks (CLAUDE.md SS4): a real in-memory Binary double whose
get_functions() yields an empty address space.
"""

from tests._doubles.zero_complexity_binary import ZeroComplexityBinary

from r2morph.devirtualization.iterative_simplifier import (
    IterativeSimplifier,
    SimplificationPhase,
    SimplificationStrategy,
)


def test_zero_complexity_binary_converges_without_division_error() -> None:
    simplifier = IterativeSimplifier(ZeroComplexityBinary())
    simplifier.max_iterations = 5
    simplifier.timeout = 10

    result = simplifier.simplify(strategy=SimplificationStrategy.CONSERVATIVE)

    assert result.success is True
    assert not any("division by zero" in e for e in result.errors)
    assert SimplificationPhase.ANALYSIS in result.phases_completed
    assert SimplificationPhase.VALIDATION in result.phases_completed
