"""Analysis helpers for symbolic constraint solving."""

from __future__ import annotations

import logging
import time
from typing import Any

from r2morph.analysis.symbolic.constraint_solver_models import MBAExpression, SolverResult

logger = logging.getLogger(__name__)


def detect_opaque_predicates(
    branch_constraints: list[Any],
    z3_module: Any,
    convert_single_constraint: Any,
) -> list[dict[str, Any]]:
    """Detect opaque predicates in branch constraints."""
    if z3_module is None:
        return []

    opaque_predicates: list[dict[str, Any]] = []

    for index, constraint in enumerate(branch_constraints):
        always_true = is_constraint_always_true(constraint, z3_module, convert_single_constraint)
        always_false = is_constraint_always_false(constraint, z3_module, convert_single_constraint)

        if always_true or always_false:
            opaque_predicates.append(
                {
                    "constraint_index": index,
                    "constraint": str(constraint),
                    "always_true": always_true,
                    "always_false": always_false,
                    "confidence": 0.9,
                }
            )

    logger.info(f"Detected {len(opaque_predicates)} opaque predicates")
    return opaque_predicates


def is_constraint_always_true(constraint: Any, z3_module: Any, convert_single_constraint: Any) -> bool:
    """Check if a constraint is a tautology."""
    if z3_module is None:
        return False

    try:
        solver = z3_module.Solver()
        solver.set("timeout", 5000)

        z3_constraint = convert_single_constraint(constraint)
        if z3_constraint is not None:
            solver.add(z3_module.Not(z3_constraint))
            return bool(solver.check() == z3_module.unsat)
    except Exception as exc:
        logger.debug(f"Error checking tautology: {exc}")

    return False


def is_constraint_always_false(constraint: Any, z3_module: Any, convert_single_constraint: Any) -> bool:
    """Check if a constraint is a contradiction."""
    if z3_module is None:
        return False

    try:
        solver = z3_module.Solver()
        solver.set("timeout", 5000)

        z3_constraint = convert_single_constraint(constraint)
        if z3_constraint is not None:
            solver.add(z3_constraint)
            return bool(solver.check() == z3_module.unsat)
    except Exception as exc:
        logger.debug(f"Error checking contradiction: {exc}")

    return False


def simplify_mba_expression(
    mba: MBAExpression,
    z3_module: Any,
    parse_mba_to_z3: Any,
) -> SolverResult:
    """Simplify an MBA expression through Z3."""
    start_time = time.time()

    if z3_module is None:
        return SolverResult(satisfiable=False, solver_used="none", solving_time=time.time() - start_time)

    try:
        z3_expr = parse_mba_to_z3(mba)
        if z3_expr is None:
            return SolverResult(satisfiable=False, solving_time=time.time() - start_time, solver_used="z3")

        simplified = z3_module.simplify(z3_expr)
        simplified_str = str(simplified)

        original_complexity = len(mba.expression)
        simplified_complexity = len(simplified_str)
        confidence = min(1.0, (original_complexity - simplified_complexity) / original_complexity)

        return SolverResult(
            satisfiable=True,
            simplified_expression=simplified_str,
            solving_time=time.time() - start_time,
            solver_used="z3",
            confidence=max(0.1, confidence),
        )
    except Exception as exc:
        logger.error(f"Error simplifying MBA expression: {exc}")
        return SolverResult(satisfiable=False, solving_time=time.time() - start_time, solver_used="z3")


def check_semantic_equivalence(
    expr1: str,
    expr2: str,
    variables: set[str],
    z3_module: Any,
    parse_expression_to_z3: Any,
    timeout: int,
) -> SolverResult:
    """Check whether two expressions are semantically equivalent."""
    start_time = time.time()

    if z3_module is None:
        return SolverResult(satisfiable=False, solver_used="none", solving_time=time.time() - start_time)

    try:
        solver = z3_module.Solver()
        solver.set("timeout", timeout * 1000)

        z3_vars: dict[str, Any] = {}
        for variable in variables:
            z3_vars[variable] = z3_module.BitVec(variable, 64)

        z3_expr1 = parse_expression_to_z3(expr1, z3_vars)
        z3_expr2 = parse_expression_to_z3(expr2, z3_vars)

        if z3_expr1 is None or z3_expr2 is None:
            return SolverResult(satisfiable=False, solving_time=time.time() - start_time, solver_used="z3")

        solver.add(z3_expr1 != z3_expr2)
        solving_time = time.time() - start_time

        if solver.check() == z3_module.unsat:
            return SolverResult(
                satisfiable=True,
                solving_time=solving_time,
                solver_used="z3",
                confidence=0.95,
            )

        return SolverResult(
            satisfiable=False,
            solving_time=solving_time,
            solver_used="z3",
            confidence=0.95,
        )
    except Exception as exc:
        logger.error(f"Error checking semantic equivalence: {exc}")
        return SolverResult(satisfiable=False, solving_time=time.time() - start_time, solver_used="z3")
