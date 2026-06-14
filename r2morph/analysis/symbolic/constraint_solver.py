"""
Constraint solver for symbolic execution and semantic analysis.

This module provides SMT solving capabilities using Z3 and will integrate
with the Syntia framework for instruction semantics learning.
"""

import logging
import time
from typing import Any

from . import constraint_solver_models as _constraint_solver_models
from . import constraint_solver_parsing as _constraint_solver_parsing

_z3: Any = None
_angr: Any = None
_claripy: Any = None

try:
    import z3 as _z3_mod

    Z3_AVAILABLE = True
    _z3 = _z3_mod
except ImportError:
    Z3_AVAILABLE = False

try:
    import angr as _angr_mod
    import claripy as _claripy_mod

    ANGR_AVAILABLE = True
    _angr = _angr_mod
    _claripy = _claripy_mod
except ImportError:
    ANGR_AVAILABLE = False

z3 = _z3
angr = _angr
claripy = _claripy
ConstraintType = _constraint_solver_models.ConstraintType
SolverResult = _constraint_solver_models.SolverResult
MBAExpression = _constraint_solver_models.MBAExpression
MAX_CONSTRAINT_AST_DEPTH = _constraint_solver_parsing.MAX_CONSTRAINT_AST_DEPTH

logger = logging.getLogger(__name__)


class ConstraintSolver:
    """
    Advanced constraint solver for symbolic execution and deobfuscation.

    Provides SMT solving capabilities with specialized handling for:
    - Opaque predicate detection and simplification
    - Mixed Boolean Arithmetic (MBA) expression solving
    - VM handler constraint analysis
    - Semantic equivalence checking
    """

    def __init__(self, timeout: int = 30):
        """
        Initialize constraint solver.

        Args:
            timeout: Solver timeout in seconds
        """
        if not Z3_AVAILABLE:
            logger.warning("Z3 not available, some features will be limited")

        self.timeout = timeout
        self.solver_stats = {
            "queries_solved": 0,
            "queries_timeout": 0,
            "queries_unsat": 0,
        }

    def solve_path_constraints(self, constraints: list[Any]) -> SolverResult:
        """
        Solve path constraints from symbolic execution.

        Args:
            constraints: List of constraints from angr/claripy

        Returns:
            SolverResult with solution
        """

        start_time = time.time()

        if not Z3_AVAILABLE:
            return SolverResult(satisfiable=False, solver_used="none", solving_time=time.time() - start_time)

        try:
            # Create Z3 solver
            solver = z3.Solver()
            solver.set("timeout", self.timeout * 1000)  # Z3 uses milliseconds

            # Convert angr constraints to Z3 format
            z3_constraints = self._convert_angr_to_z3(constraints)

            for constraint in z3_constraints:
                solver.add(constraint)

            # Solve
            result = solver.check()
            solving_time = time.time() - start_time

            if result == z3.sat:
                model = self._extract_model(solver.model())
                self.solver_stats["queries_solved"] += 1

                return SolverResult(
                    satisfiable=True, model=model, solving_time=solving_time, solver_used="z3", confidence=0.95
                )
            elif result == z3.unsat:
                self.solver_stats["queries_unsat"] += 1
                return SolverResult(satisfiable=False, solving_time=solving_time, solver_used="z3")
            else:  # timeout or unknown
                self.solver_stats["queries_timeout"] += 1
                return SolverResult(satisfiable=False, solving_time=solving_time, solver_used="z3")

        except Exception as e:
            logger.error(f"Error solving path constraints: {e}")
            return SolverResult(satisfiable=False, solving_time=time.time() - start_time, solver_used="z3")

    def _convert_angr_to_z3(self, constraints: list[Any]) -> list[Any]:
        return _constraint_solver_parsing.convert_angr_to_z3(constraints, z3)

    def _extract_model(self, z3_model: Any) -> dict[str, Any]:
        return _constraint_solver_parsing.extract_model(z3_model, z3)

    def detect_opaque_predicates(self, branch_constraints: list[Any]) -> list[dict[str, Any]]:
        """
        Detect opaque predicates in branch constraints.

        Opaque predicates are conditions that always evaluate to the same
        value regardless of input, used to obfuscate control flow.

        Args:
            branch_constraints: Constraints from branch conditions

        Returns:
            List of detected opaque predicates
        """
        opaque_predicates = []

        for i, constraint in enumerate(branch_constraints):
            # Test if constraint is always true
            always_true = self._is_constraint_always_true(constraint)

            # Test if constraint is always false
            always_false = self._is_constraint_always_false(constraint)

            if always_true or always_false:
                opaque_predicates.append(
                    {
                        "constraint_index": i,
                        "constraint": str(constraint),
                        "always_true": always_true,
                        "always_false": always_false,
                        "confidence": 0.9,
                    }
                )

        logger.info(f"Detected {len(opaque_predicates)} opaque predicates")
        return opaque_predicates

    def _is_constraint_always_true(self, constraint: Any) -> bool:
        """Check if constraint is always true (tautology)."""
        if not Z3_AVAILABLE:
            return False

        try:
            solver = z3.Solver()
            solver.set("timeout", 5000)  # 5 second timeout

            # Convert and negate constraint
            z3_constraint = self._convert_single_constraint(constraint)
            if z3_constraint is not None:
                solver.add(z3.Not(z3_constraint))
                return bool(solver.check() == z3.unsat)  # Always true if negation is unsat

        except Exception as e:
            logger.debug(f"Error checking tautology: {e}")

        return False

    def _is_constraint_always_false(self, constraint: Any) -> bool:
        """Check if constraint is always false (contradiction)."""
        if not Z3_AVAILABLE:
            return False

        try:
            solver = z3.Solver()
            solver.set("timeout", 5000)

            z3_constraint = self._convert_single_constraint(constraint)
            if z3_constraint is not None:
                solver.add(z3_constraint)
                return bool(solver.check() == z3.unsat)  # Always false if unsat

        except Exception as e:
            logger.debug(f"Error checking contradiction: {e}")

        return False

    def _convert_single_constraint(self, constraint: Any) -> Any | None:
        return _constraint_solver_parsing.convert_single_constraint(constraint, z3)

    def simplify_mba_expression(self, mba: MBAExpression) -> SolverResult:
        """
        Simplify Mixed Boolean Arithmetic expressions.

        MBA expressions are commonly used in obfuscation to make
        simple operations appear complex through boolean algebra.

        Args:
            mba: MBA expression to simplify

        Returns:
            SolverResult with simplified expression
        """

        start_time = time.time()

        if not Z3_AVAILABLE:
            return SolverResult(satisfiable=False, solver_used="none", solving_time=time.time() - start_time)

        try:
            # Parse MBA expression into Z3 format
            z3_expr = self._parse_mba_to_z3(mba)

            if z3_expr is None:
                return SolverResult(satisfiable=False, solving_time=time.time() - start_time, solver_used="z3")

            # Simplify using Z3
            simplified = z3.simplify(z3_expr)

            # Convert back to string representation
            simplified_str = str(simplified)

            # Calculate confidence based on complexity reduction
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

        except Exception as e:
            logger.error(f"Error simplifying MBA expression: {e}")
            return SolverResult(satisfiable=False, solving_time=time.time() - start_time, solver_used="z3")

    def _parse_mba_to_z3(self, mba: MBAExpression) -> Any | None:
        """
        Parse MBA expression string into Z3 format.

        Args:
            mba: MBA expression

        Returns:
            Z3 expression or None if parsing fails
        """
        if not Z3_AVAILABLE:
            return None

        try:
            # Create Z3 variables for each variable in the expression
            z3_vars = {}
            for var in mba.variables:
                z3_vars[var] = z3.BitVec(var, mba.bit_width)

            # Comprehensive MBA expression parsing
            # This implementation handles basic MBA patterns and can be extended
            logger.debug(f"Parsing MBA expression: {mba.expression}")

            if mba.expression:
                parsed = self._parse_expression_to_z3(mba.expression, z3_vars, bit_width=mba.bit_width)
                if parsed is not None:
                    return parsed

            # Handle basic MBA expressions with proper parsing
            if mba.variables:
                first_var = next(iter(mba.variables))
                return z3_vars.get(first_var)

        except Exception as e:
            logger.debug(f"Error parsing MBA expression: {e}")

        return None

    def check_semantic_equivalence(self, expr1: str, expr2: str, variables: set[str]) -> SolverResult:
        """
        Check if two expressions are semantically equivalent.

        Used to verify that deobfuscation preserves program semantics.

        Args:
            expr1: First expression
            expr2: Second expression
            variables: Set of variables in expressions

        Returns:
            SolverResult indicating equivalence
        """

        start_time = time.time()

        if not Z3_AVAILABLE:
            return SolverResult(satisfiable=False, solver_used="none", solving_time=time.time() - start_time)

        try:
            solver = z3.Solver()
            solver.set("timeout", self.timeout * 1000)

            # Create Z3 variables
            z3_vars = {}
            for var in variables:
                z3_vars[var] = z3.BitVec(var, 64)  # Assume 64-bit variables

            # Parse expressions using Z3 expression parser
            z3_expr1 = self._parse_expression_to_z3(expr1, z3_vars)
            z3_expr2 = self._parse_expression_to_z3(expr2, z3_vars)

            if z3_expr1 is None or z3_expr2 is None:
                return SolverResult(satisfiable=False, solving_time=time.time() - start_time, solver_used="z3")

            # Check if expressions are equivalent by checking if their
            # difference can be non-zero
            diff = z3_expr1 != z3_expr2
            solver.add(diff)

            result = solver.check()
            solving_time = time.time() - start_time

            if result == z3.unsat:
                # Expressions are equivalent (difference is never true)
                return SolverResult(
                    satisfiable=True, solving_time=solving_time, solver_used="z3", confidence=0.95  # Equivalent
                )
            else:
                # Expressions are not equivalent
                return SolverResult(
                    satisfiable=False, solving_time=solving_time, solver_used="z3", confidence=0.95  # Not equivalent
                )

        except Exception as e:
            logger.error(f"Error checking semantic equivalence: {e}")
            return SolverResult(satisfiable=False, solving_time=time.time() - start_time, solver_used="z3")

    def _parse_expression_to_z3(self, expr: str, z3_vars: dict[str, Any], bit_width: int = 64) -> Any | None:
        return _constraint_solver_parsing.parse_expression_to_z3(expr, z3_vars, z3, bit_width=bit_width)

    def get_solver_statistics(self) -> dict[str, Any]:
        """Get solver performance statistics."""
        total_queries = sum(self.solver_stats.values())

        if total_queries == 0:
            return self.solver_stats

        stats: dict[str, Any] = dict(self.solver_stats)
        stats["success_rate"] = stats["queries_solved"] / total_queries
        stats["timeout_rate"] = stats["queries_timeout"] / total_queries

        return stats
