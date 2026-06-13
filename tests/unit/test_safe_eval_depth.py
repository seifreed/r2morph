"""Regression tests for the §10 recursion bound in safe_eval_arithmetic_node.

A deeply nested expression (e.g. adversarial MBA from a sample) must be
rejected with a clean ValueError before it can exhaust the interpreter
stack, while ordinary nesting still folds correctly.
"""

import ast

import pytest

from r2morph.core.safe_eval import MAX_AST_DEPTH, safe_eval_arithmetic_node


def _nest_unary(depth: int) -> ast.AST:
    node: ast.AST = ast.Constant(value=0)
    for _ in range(depth):
        node = ast.UnaryOp(op=ast.USub(), operand=node)
    return node


def test_depth_over_limit_raises_value_error():
    node = _nest_unary(MAX_AST_DEPTH + 5)
    with pytest.raises(ValueError, match="depth"):
        safe_eval_arithmetic_node(node)


def test_depth_at_limit_still_evaluates():
    # MAX_AST_DEPTH nested negations of 0 collapse to 0 without tripping the guard
    node = _nest_unary(MAX_AST_DEPTH)
    assert safe_eval_arithmetic_node(node) == 0


def test_shallow_expression_unaffected():
    tree = ast.parse("1 + 2 * 3", mode="eval")
    assert safe_eval_arithmetic_node(tree.body) == 7
