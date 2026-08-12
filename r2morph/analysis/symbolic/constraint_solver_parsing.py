"""Pure conversion and parsing helpers for symbolic constraint solving."""

from __future__ import annotations

import ast
import logging
import operator
from collections.abc import Callable
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

_UNARY_OPERATORS: dict[type[ast.unaryop], Callable[[Any], Any]] = {
    ast.Invert: operator.invert,
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}
_BINARY_OPERATORS: dict[type[ast.operator], Callable[[Any, Any], Any]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.BitAnd: operator.and_,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.Mod: operator.mod,
}
_COMPARISON_OPERATORS: dict[type[ast.cmpop], Callable[[Any, Any], Any]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}


class _ExpressionConverter:
    def __init__(self, z3_vars: dict[str, Any], z3: Any, bit_width: int) -> None:
        self.z3_vars = z3_vars
        self.z3 = z3
        self.bit_width = bit_width
        self.converters: dict[type[ast.AST], Callable[[Any, int], Any | None]] = {
            ast.Name: self._convert_name,
            ast.Constant: self._convert_constant,
            ast.UnaryOp: self._convert_unary,
            ast.BinOp: self._convert_binary,
            ast.BoolOp: self._convert_boolean,
            ast.Compare: self._convert_comparison,
        }

    def convert(self, node: ast.AST, depth: int = 0) -> Any | None:
        if depth > MAX_CONSTRAINT_AST_DEPTH:
            return None
        converter = self.converters.get(type(node))
        return converter(node, depth) if converter is not None else None

    def _convert_name(self, node: ast.Name, _depth: int) -> Any:
        if node.id not in self.z3_vars:
            self.z3_vars[node.id] = self.z3.BitVec(node.id, self.bit_width)
        return self.z3_vars[node.id]

    def _convert_constant(self, node: ast.Constant, _depth: int) -> Any | None:
        if isinstance(node.value, bool):
            return self.z3.BoolVal(node.value)
        if isinstance(node.value, int):
            return self.z3.BitVecVal(node.value, self.bit_width)
        return None

    def _convert_unary(self, node: ast.UnaryOp, depth: int) -> Any | None:
        operand = self.convert(node.operand, depth + 1)
        operation = _UNARY_OPERATORS.get(type(node.op))
        return operation(operand) if operand is not None and operation is not None else None

    def _convert_binary(self, node: ast.BinOp, depth: int) -> Any | None:
        left = self.convert(node.left, depth + 1)
        right = self.convert(node.right, depth + 1)
        operation = _BINARY_OPERATORS.get(type(node.op))
        return operation(left, right) if left is not None and right is not None and operation is not None else None

    def _convert_boolean(self, node: ast.BoolOp, depth: int) -> Any | None:
        values = [self.convert(value, depth + 1) for value in node.values]
        if any(value is None for value in values):
            return None
        if isinstance(node.op, ast.And):
            return self.z3.And(*values)
        if isinstance(node.op, ast.Or):
            return self.z3.Or(*values)
        return None

    def _convert_comparison(self, node: ast.Compare, depth: int) -> Any | None:
        if len(node.ops) != 1 or len(node.comparators) != 1:
            return None
        left = self.convert(node.left, depth + 1)
        right = self.convert(node.comparators[0], depth + 1)
        operation = _COMPARISON_OPERATORS.get(type(node.ops[0]))
        return operation(left, right) if left is not None and right is not None and operation is not None else None


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

    try:
        parsed = ast.parse(expr, mode="eval")
        return _ExpressionConverter(z3_vars, z3, bit_width).convert(parsed.body)
    except Exception as e:
        logger.debug("Error parsing expression '%s': %s", expr, e)
        return None
