"""Pure conversion and parsing helpers for symbolic constraint solving."""

from __future__ import annotations

import ast
import logging
from typing import Any

from r2morph.analysis.symbolic.constraint_solver_conversions import (
    convert_angr_to_z3 as _convert_angr_to_z3,
)
from r2morph.analysis.symbolic.constraint_solver_conversions import (
    convert_single_constraint as _convert_single_constraint,
)
from r2morph.analysis.symbolic.constraint_solver_conversions import (
    extract_model as _extract_model,
)

logger = logging.getLogger(__name__)

# Bound recursion when translating a parsed expression tree into Z3 so that an
# adversarially nested expression from a sample cannot exhaust the stack. 256 is
# far above any real constraint yet well under Python's default recursion limit.
MAX_CONSTRAINT_AST_DEPTH = 256


def convert_angr_to_z3(constraints: list[Any], z3: Any | None) -> list[Any]:
    return _convert_angr_to_z3(constraints, z3)


def extract_model(z3_model: Any, z3: Any | None) -> dict[str, Any]:
    return _extract_model(z3_model, z3)


def convert_single_constraint(constraint: Any, z3: Any | None) -> Any | None:
    return _convert_single_constraint(constraint, z3)


def parse_expression_to_z3(
    expr: str,
    z3_vars: dict[str, Any],
    z3: Any | None,
    bit_width: int = 64,
) -> Any | None:
    """Parse an expression string to a Z3 expression."""
    if z3 is None:
        return None

    logger.debug("Parsing expression: %s", expr)

    def to_z3(node: ast.AST, _depth: int = 0) -> Any | None:
        if _depth > MAX_CONSTRAINT_AST_DEPTH:
            return None
        if isinstance(node, ast.Name):
            if node.id not in z3_vars:
                z3_vars[node.id] = z3.BitVec(node.id, bit_width)
            return z3_vars[node.id]
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return z3.BoolVal(node.value)
            if isinstance(node.value, int):
                return z3.BitVecVal(node.value, bit_width)
            return None
        if isinstance(node, ast.UnaryOp):
            operand = to_z3(node.operand, _depth + 1)
            if operand is None:
                return None
            if isinstance(node.op, ast.Invert):
                return ~operand
            if isinstance(node.op, ast.UAdd):
                return operand
            if isinstance(node.op, ast.USub):
                return -operand
        if isinstance(node, ast.BinOp):
            left = to_z3(node.left, _depth + 1)
            right = to_z3(node.right, _depth + 1)
            if left is None or right is None:
                return None
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.BitAnd):
                return left & right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
            if isinstance(node.op, ast.LShift):
                return left << right
            if isinstance(node.op, ast.RShift):
                return left >> right
            if isinstance(node.op, ast.Mod):
                return left % right
        if isinstance(node, ast.BoolOp):
            values = [to_z3(value, _depth + 1) for value in node.values]
            if any(value is None for value in values):
                return None
            if isinstance(node.op, ast.And):
                return z3.And(*values)
            if isinstance(node.op, ast.Or):
                return z3.Or(*values)
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            left = to_z3(node.left, _depth + 1)
            right = to_z3(node.comparators[0], _depth + 1)
            if left is None or right is None:
                return None
            op = node.ops[0]
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
            if isinstance(op, ast.Lt):
                return left < right
            if isinstance(op, ast.LtE):
                return left <= right
            if isinstance(op, ast.Gt):
                return left > right
            if isinstance(op, ast.GtE):
                return left >= right
        return None

    try:
        parsed = ast.parse(expr, mode="eval")
        return to_z3(parsed.body)
    except Exception as e:
        logger.debug("Error parsing expression '%s': %s", expr, e)
        return None
