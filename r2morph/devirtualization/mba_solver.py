"""
Mixed Boolean Arithmetic (MBA) solver for simplifying obfuscated expressions.

This module provides sophisticated MBA expression analysis and simplification
using Z3 SMT solver and pattern matching techniques. MBA expressions are
commonly used in obfuscation to make simple arithmetic operations appear complex.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from .mba_solver_helpers import (
    assess_complexity,
    calculate_complexity_reduction,
    calculate_parentheses_depth,
    calculate_polynomial_degree,
    cleanup_z3_output,
    count_coefficients,
    evaluate_expression,
    extract_variables,
    find_simple_equivalent,
    generate_native_equivalent,
    is_linear_mba,
    load_mba_patterns,
)

if TYPE_CHECKING:
    import z3
else:
    try:
        import z3
    except ImportError:
        z3 = None

Z3_AVAILABLE = z3 is not None

logger = logging.getLogger(__name__)


class MBAComplexity(Enum):
    """MBA expression complexity levels."""

    SIMPLE = "simple"  # Basic linear MBA
    MEDIUM = "medium"  # Polynomial MBA
    COMPLEX = "complex"  # High-degree polynomial or mixed
    UNKNOWN = "unknown"  # Cannot determine complexity


@dataclass
class MBAExpression:
    """Represents an MBA expression with metadata."""

    expression: str
    variables: set[str] = field(default_factory=set)
    bit_width: int = 64
    complexity: MBAComplexity = MBAComplexity.UNKNOWN
    original_form: str | None = None
    simplified_form: str | None = None
    is_linear: bool = False
    degree: int = 0
    coefficient_count: int = 0


@dataclass
class SimplificationResult:
    """Result of MBA simplification."""

    success: bool = False
    original_expression: str = ""
    simplified_expression: str | None = None
    complexity_reduction: float = 0.0
    solving_time: float = 0.0
    method_used: str = "unknown"
    confidence: float = 0.0
    equivalent_native: str | None = None


class MBASolver:
    """
    Mixed Boolean Arithmetic solver and simplifier.

    Provides various techniques for simplifying MBA expressions:
    - Z3-based symbolic simplification
    - Pattern-based substitution
    - Polynomial reduction
    - Truth table analysis for small expressions
    """

    def __init__(self, timeout: int = 30, max_variables: int = 8):
        """
        Initialize MBA solver.

        Args:
            timeout: Timeout for Z3 operations (seconds)
            max_variables: Maximum variables for exhaustive analysis
        """
        if not Z3_AVAILABLE:
            logger.warning("Z3 not available, MBA solving will be limited")

        self.timeout = timeout
        self.max_variables = max_variables
        self.known_patterns = load_mba_patterns()

        self.stats = {
            "expressions_analyzed": 0,
            "expressions_simplified": 0,
            "pattern_matches": 0,
            "z3_simplifications": 0,
        }

    def analyze_mba_expression(self, expression: str) -> MBAExpression:
        """
        Analyze an MBA expression to understand its structure.

        Args:
            expression: MBA expression string

        Returns:
            MBA expression analysis
        """
        self.stats["expressions_analyzed"] += 1

        mba = MBAExpression(expression=expression, original_form=expression)

        mba.variables = self._extract_variables(expression)
        mba.complexity = self._assess_complexity(expression)
        mba.is_linear = self._is_linear_mba(expression)
        mba.degree = self._calculate_polynomial_degree(expression)
        mba.coefficient_count = self._count_coefficients(expression)

        logger.debug(f"MBA analysis: {len(mba.variables)} vars, complexity={mba.complexity.value}")

        return mba

    def _extract_variables(self, expression: str) -> set[str]:
        """Extract variable names from expression."""
        return extract_variables(expression)

    def _assess_complexity(self, expression: str) -> MBAComplexity:
        """Assess the complexity of an MBA expression."""
        return MBAComplexity(assess_complexity(expression))

    def _calculate_parentheses_depth(self, expression: str) -> int:
        """Calculate maximum parentheses nesting depth."""
        return calculate_parentheses_depth(expression)

    def _is_linear_mba(self, expression: str) -> bool:
        """Check if expression is a linear MBA."""
        return is_linear_mba(expression)

    def _calculate_polynomial_degree(self, expression: str) -> int:
        """Calculate polynomial degree (simplified estimation)."""
        return calculate_polynomial_degree(expression)

    def _count_coefficients(self, expression: str) -> int:
        """Count numeric coefficients in expression."""
        return count_coefficients(expression)

    def simplify_mba(self, expression: str, method: str = "auto") -> SimplificationResult:
        """
        Simplify an MBA expression using specified method.

        Args:
            expression: MBA expression to simplify
            method: Simplification method ("auto", "z3", "patterns", "truth_table")

        Returns:
            Simplification result
        """

        start_time = time.time()

        result = SimplificationResult(original_expression=expression, method_used=method)

        try:
            mba = self.analyze_mba_expression(expression)

            if method == "auto":
                if len(mba.variables) <= 3 and mba.complexity == MBAComplexity.SIMPLE:
                    method = "truth_table"
                elif mba.complexity == MBAComplexity.SIMPLE:
                    method = "patterns"
                else:
                    method = "z3"

            if method == "patterns":
                simplified = self._simplify_with_patterns(expression)
            elif method == "z3" and Z3_AVAILABLE:
                simplified = self._simplify_with_z3(mba)
            elif method == "truth_table":
                simplified = self._simplify_with_truth_table(mba)
            else:
                simplified = None

            if simplified and simplified != expression:
                result.success = True
                result.simplified_expression = simplified
                result.complexity_reduction = self._calculate_complexity_reduction(expression, simplified)
                result.confidence = 0.8 if method == "z3" else 0.6
                result.equivalent_native = self._generate_native_equivalent(simplified)

                self.stats["expressions_simplified"] += 1

                if method == "patterns":
                    self.stats["pattern_matches"] += 1
                elif method == "z3":
                    self.stats["z3_simplifications"] += 1

        except Exception as e:
            logger.error(f"Error simplifying MBA expression: {e}")
            result.success = False

        result.solving_time = time.time() - start_time
        return result

    def _simplify_with_patterns(self, expression: str) -> str | None:
        """Simplify using pattern matching."""
        simplified = expression

        for pattern, replacement in self.known_patterns.items():
            try:
                if replacement == "optimize_complex":
                    continue

                new_expr = re.sub(pattern, replacement, simplified, flags=re.IGNORECASE)
                if new_expr != simplified:
                    simplified = new_expr
                    logger.debug(f"Applied pattern: {pattern}")
                    break
            except Exception as e:
                logger.debug(f"Pattern matching error: {e}")
                continue

        return simplified if simplified != expression else None

    def _simplify_with_z3(self, mba: MBAExpression) -> str | None:
        """Simplify using Z3 SMT solver."""
        if not Z3_AVAILABLE:
            return None

        try:
            z3_vars = {}
            for var in mba.variables:
                z3_vars[var] = z3.BitVec(var, mba.bit_width)

            z3_expr = self._parse_expression_to_z3(mba.expression, z3_vars)

            if z3_expr is not None:
                simplified_z3 = z3.simplify(z3_expr)
                simplified_str = str(simplified_z3)
                simplified_str = self._cleanup_z3_output(simplified_str)

                return simplified_str

        except Exception as e:
            logger.debug(f"Z3 simplification error: {e}")

        return None

    def _parse_expression_to_z3(self, expression: str, z3_vars: dict[str, Any]) -> Any | None:
        """Parse expression to Z3 format (simplified implementation)."""
        if not Z3_AVAILABLE:
            return None

        try:
            # This is a very simplified parser - a real implementation would need
            # a proper expression parser for MBA expressions

            for op in ["+", "-", "*", "&", "|", "^"]:
                if op in expression:
                    parts = expression.split(op, 1)
                    if len(parts) == 2:
                        left = parts[0].strip()
                        right = parts[1].strip()

                        left_z3 = self._parse_operand_to_z3(left, z3_vars)
                        right_z3 = self._parse_operand_to_z3(right, z3_vars)

                        if left_z3 is not None and right_z3 is not None:
                            if op == "+":
                                return left_z3 + right_z3
                            elif op == "-":
                                return left_z3 - right_z3
                            elif op == "*":
                                return left_z3 * right_z3
                            elif op == "&":
                                return left_z3 & right_z3
                            elif op == "|":
                                return left_z3 | right_z3
                            elif op == "^":
                                return left_z3 ^ right_z3

            return self._parse_operand_to_z3(expression, z3_vars)

        except Exception as e:
            logger.debug(f"Z3 parsing error: {e}")
            return None

    def _parse_operand_to_z3(self, operand: str, z3_vars: dict[str, Any]) -> Any | None:
        """Parse single operand to Z3."""
        operand = operand.strip()

        if operand in z3_vars:
            return z3_vars[operand]

        try:
            num = int(operand)
            return z3.BitVecVal(num, 64)
        except ValueError:
            # Not a parseable numeric literal here (e.g. register/symbolic operand); expected, so this candidate is skipped.
            pass

        return None

    def _cleanup_z3_output(self, z3_output: str) -> str:
        """Clean up Z3 output formatting."""
        return cleanup_z3_output(z3_output)

    def _simplify_with_truth_table(self, mba: MBAExpression) -> str | None:
        """Simplify using truth table analysis (for small expressions)."""
        if len(mba.variables) > self.max_variables:
            return None

        try:
            variables = list(mba.variables)
            n_vars = len(variables)

            if n_vars == 0:
                return None

            truth_table = {}

            for i in range(2**n_vars):
                assignment = {}
                for j, var in enumerate(variables):
                    assignment[var] = (i >> j) & 1

                try:
                    result = self._evaluate_expression(mba.expression, assignment)
                    truth_table[tuple(assignment[var] for var in variables)] = result
                except Exception as e:
                    logger.debug(f"Expression evaluation failed: {e}")
                    return None

            simplified = self._find_simple_equivalent(truth_table, variables)
            return simplified

        except Exception as e:
            logger.debug(f"Truth table simplification error: {e}")
            return None

    def _evaluate_expression(self, expression: str, assignment: dict[str, int]) -> int:
        """Evaluate expression with given variable assignment using safe AST evaluation."""
        return evaluate_expression(expression, assignment)

    def _find_simple_equivalent(self, truth_table: dict[tuple, int], variables: list[str]) -> str | None:
        """Find simple equivalent expression from truth table."""
        return find_simple_equivalent(truth_table, variables)

    def _calculate_complexity_reduction(self, original: str, simplified: str) -> float:
        """Calculate complexity reduction percentage."""
        return calculate_complexity_reduction(original, simplified)

    def _generate_native_equivalent(self, simplified_expr: str) -> str | None:
        """Generate equivalent native assembly code."""
        return generate_native_equivalent(simplified_expr)

    def get_solver_statistics(self) -> dict[str, Any]:
        """Get solver performance statistics."""
        total = self.stats["expressions_analyzed"]

        stats: dict[str, Any] = dict(self.stats)
        if total > 0:
            stats["success_rate"] = self.stats["expressions_simplified"] / total
            stats["pattern_success_rate"] = self.stats["pattern_matches"] / total
        else:
            stats["success_rate"] = 0.0
            stats["pattern_success_rate"] = 0.0

        return stats
