"""Safe evaluation of constant arithmetic AST expressions.

Shared by the MBA solver and the Syntia framework to fold fully-substituted
numeric expressions without ever calling ``eval``. Only integer/float
constants and a fixed set of bitwise/arithmetic operators are permitted.
"""

from __future__ import annotations

import ast
from typing import Any

# Safe operator tables for evaluating arithmetic AST nodes
_SAFE_BINOPS = {
    ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b,
    ast.BitXor: lambda a, b: a ^ b,
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.LShift: lambda a, b: a << b,
    ast.RShift: lambda a, b: a >> b,
}
_SAFE_UNARYOPS = {
    ast.Invert: lambda a: ~a,
    ast.USub: lambda a: -a,
    ast.UAdd: lambda a: +a,
}


def safe_eval_arithmetic_node(node: Any) -> int:
    """Recursively evaluate an AST node, allowing only safe operations.

    Raises ``ValueError`` for any operator or node type outside the safe set.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return int(node.value)
    if isinstance(node, ast.BinOp):
        bin_func = _SAFE_BINOPS.get(type(node.op))
        if bin_func is None:
            raise ValueError(f"Unsupported binary operator: {type(node.op).__name__}")
        left = safe_eval_arithmetic_node(node.left)
        right = safe_eval_arithmetic_node(node.right)
        return int(bin_func(left, right))
    if isinstance(node, ast.UnaryOp):
        unary_func = _SAFE_UNARYOPS.get(type(node.op))
        if unary_func is None:
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        operand = safe_eval_arithmetic_node(node.operand)
        return int(unary_func(operand))
    raise ValueError(f"Unsupported AST node type: {type(node).__name__}")
