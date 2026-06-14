"""Pure conversion and parsing helpers for symbolic constraint solving."""

from __future__ import annotations

import ast
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Bound recursion when translating a parsed expression tree into Z3 so that an
# adversarially nested expression from a sample cannot exhaust the stack. 256 is
# far above any real constraint yet well under Python's default recursion limit.
MAX_CONSTRAINT_AST_DEPTH = 256


def convert_angr_to_z3(constraints: list[Any], z3: Any | None) -> list[Any]:
    """Convert angr/claripy constraints to Z3 format."""
    z3_constraints: list[Any] = []

    if z3 is None:
        return z3_constraints

    try:
        for constraint in constraints:
            if isinstance(constraint, z3.ExprRef):
                z3_constraints.append(constraint)
            elif hasattr(constraint, "to_z3"):
                z3_constraints.append(constraint.to_z3())
            else:
                logger.debug("Could not convert constraint: %s", constraint)
    except Exception as e:
        logger.debug("Error converting constraints: %s", e)

    return z3_constraints


def extract_model(z3_model: Any, z3: Any | None) -> dict[str, Any]:
    """Extract model values from a Z3 solution."""
    model: dict[str, Any] = {}

    if z3 is None or z3_model is None:
        return model

    try:
        for decl in z3_model:
            var_name = str(decl)
            value = z3_model[decl]

            if z3.is_int_value(value):
                model[var_name] = value.as_long()
            elif z3.is_bv_value(value):
                model[var_name] = value.as_long()
            elif z3.is_bool(value):
                model[var_name] = z3.is_true(value)
            else:
                model[var_name] = str(value)
    except Exception as e:
        logger.debug("Error extracting model: %s", e)

    return model


def convert_single_constraint(constraint: Any, z3: Any | None) -> Any | None:
    """Convert a single constraint to Z3 format."""
    if z3 is None:
        return None
    try:
        if isinstance(constraint, bool):
            return z3.BoolVal(constraint)
        if isinstance(constraint, z3.ExprRef):
            return constraint
        if hasattr(constraint, "to_z3"):
            return constraint.to_z3()
    except Exception as e:
        logger.debug("Error converting single constraint: %s", e)
    return None


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
