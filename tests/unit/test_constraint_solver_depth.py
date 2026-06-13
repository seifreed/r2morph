"""Regression test for the §10 recursion bound in _parse_expression_to_z3.

An adversarially deep expression must be rejected (returning None, the
function's existing failure signal) before the recursive Z3 translation can
exhaust the interpreter stack, while ordinary expressions still translate.
"""

import pytest

from r2morph.analysis.symbolic.constraint_solver import (
    MAX_CONSTRAINT_AST_DEPTH,
    Z3_AVAILABLE,
    ConstraintSolver,
)

if not Z3_AVAILABLE:
    pytest.skip("z3 not available", allow_module_level=True)


def test_deep_expression_rejected_by_depth_guard():
    solver = ConstraintSolver(timeout=1)
    deep = "~" * (MAX_CONSTRAINT_AST_DEPTH + 50) + "0"
    assert solver._parse_expression_to_z3(deep, {}) is None


def test_shallow_expression_still_translates():
    solver = ConstraintSolver(timeout=1)
    assert solver._parse_expression_to_z3("a + b", {}) is not None
