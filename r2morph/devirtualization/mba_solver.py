"""
Mixed Boolean Arithmetic (MBA) solver for simplifying obfuscated expressions.

This module provides sophisticated MBA expression analysis and simplification
using Z3 SMT solver and pattern matching techniques. MBA expressions are
commonly used in obfuscation to make simple arithmetic operations appear complex.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    z3 = None

logger = logging.getLogger(__name__)


class MBAComplexity(Enum):
    """MBA expression complexity levels."""
    
    SIMPLE = "simple"         # Basic linear MBA
    MEDIUM = "medium"         # Polynomial MBA
    COMPLEX = "complex"       # High-degree polynomial or mixed
    UNKNOWN = "unknown"       # Cannot determine complexity


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
        self.known_patterns = self._load_mba_patterns()
        
        # Statistics
        self.stats = {
            "expressions_analyzed": 0,
            "expressions_simplified": 0,
            "pattern_matches": 0,
            "z3_simplifications": 0,
        }
    
    def _load_mba_patterns(self) -> dict[str, str]:
        """Load known MBA patterns and their simplified forms."""
        patterns = {
            # Linear MBA patterns
            r"(.+)\s*\+\s*(.+)\s*-\s*(.+)\s*&\s*(.+)": r"\1 + \2",  # x + y - (x & y) = x | y
            r"(.+)\s*\^\s*(.+)\s*\+\s*2\s*\*\s*\((.+)\s*&\s*(.+)\)": r"\1 + \2",  # x ^ y + 2*(x & y) = x + y
            r"(.+)\s*\|\s*(.+)\s*\+\s*(.+)\s*&\s*(.+)": r"2*(\1) + 2*(\2) - (\1 + \2)",  # (x | y) + (x & y) = x + y
            
            # Boolean to arithmetic conversions
            r"(.+)\s*\&\s*(.+)\s*\|\s*\~\((.+)\s*\^\s*(.+)\)": r"\1 == \2",  # (x & y) | ~(x ^ y) = x == y
            r"\~\((.+)\s*\^\s*(.+)\)": r"\1 == \2",  # ~(x ^ y) = x == y
            
            # Common obfuscation patterns
            r"(.+)\s*\*\s*2\s*-\s*(.+)": r"\1 + (\1 - \2)",  # x*2 - y = x + (x - y)
            r"(.+)\s*\+\s*(.+)\s*\*\s*(.+)\s*-\s*(.+)": r"optimize_complex",  # Mark for complex optimization
        }
        return patterns
    
    def analyze_mba_expression(self, expression: str) -> MBAExpression:
        """
        Analyze an MBA expression to understand its structure.
        
        Args:
            expression: MBA expression string
            
        Returns:
            MBA expression analysis
        """
        self.stats["expressions_analyzed"] += 1
        
        mba = MBAExpression(
            expression=expression,
            original_form=expression
        )
        
        # Extract variables
        mba.variables = self._extract_variables(expression)
        
        # Determine complexity
        mba.complexity = self._assess_complexity(expression)
        
        # Check if linear
        mba.is_linear = self._is_linear_mba(expression)
        
        # Calculate degree
        mba.degree = self._calculate_polynomial_degree(expression)
        
        # Count coefficients
        mba.coefficient_count = self._count_coefficients(expression)
        
        logger.debug(f"MBA analysis: {len(mba.variables)} vars, complexity={mba.complexity.value}")
        
        return mba
    
    def _extract_variables(self, expression: str) -> set[str]:
        """Extract variable names from expression."""
        # Simple regex to find variable-like tokens
        import re
        
        # Find tokens that look like variables (letters followed by optional digits)
        var_pattern = r'\b[a-zA-Z][a-zA-Z0-9_]*\b'
        potential_vars = re.findall(var_pattern, expression)
        
        # Filter out operators and keywords
        operators = {'and', 'or', 'xor', 'not', 'shl', 'shr', 'add', 'sub', 'mul', 'div'}
        variables = set()
        
        for var in potential_vars:
            if var.lower() not in operators and not var.isdigit():
                variables.add(var)
        
        return variables
    
    def _assess_complexity(self, expression: str) -> MBAComplexity:
        """Assess the complexity of an MBA expression."""
        # Count operators and operations
        op_count = sum(expression.count(op) for op in ['+', '-', '*', '/', '&', '|', '^', '~'])
        paren_depth = self._calculate_parentheses_depth(expression)
        
        if op_count <= 3 and paren_depth <= 2:
            return MBAComplexity.SIMPLE
        elif op_count <= 10 and paren_depth <= 4:
            return MBAComplexity.MEDIUM
        else:
            return MBAComplexity.COMPLEX
    
    def _calculate_parentheses_depth(self, expression: str) -> int:
        """Calculate maximum parentheses nesting depth."""
        max_depth = 0
        current_depth = 0
        
        for char in expression:
            if char == '(':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == ')':
                current_depth -= 1
        
        return max_depth
    
    def _is_linear_mba(self, expression: str) -> bool:
        """Check if expression is a linear MBA."""
        # Linear MBA contains no multiplication between variables
        # This is a simplified check
        return '*' not in expression or not any(
            var1 + '*' + var2 in expression or var2 + '*' + var1 in expression
            for var1 in self._extract_variables(expression)
            for var2 in self._extract_variables(expression)
            if var1 != var2
        )
    
    def _calculate_polynomial_degree(self, expression: str) -> int:
        """Calculate polynomial degree (simplified estimation)."""
        # Count maximum multiplication depth
        max_degree = 1
        
        # Look for patterns like x*y*z to estimate degree
        mult_parts = expression.split('*')
        for part in mult_parts:
            var_count = len(self._extract_variables(part))
            max_degree = max(max_degree, var_count)
        
        return max_degree
    
    def _count_coefficients(self, expression: str) -> int:
        """Count numeric coefficients in expression."""
        import re
        
        # Find numeric constants
        number_pattern = r'\b\d+\b'
        numbers = re.findall(number_pattern, expression)
        
        return len(numbers)
    
    def simplify_mba(self, expression: str, method: str = "auto") -> SimplificationResult:
        """
        Simplify an MBA expression using specified method.
        
        Args:
            expression: MBA expression to simplify
            method: Simplification method ("auto", "z3", "patterns", "truth_table")
            
        Returns:
            Simplification result
        """
        import time
        start_time = time.time()
        
        result = SimplificationResult(
            original_expression=expression,
            method_used=method
        )
        
        try:
            mba = self.analyze_mba_expression(expression)
            
            if method == "auto":
                # Choose best method based on expression characteristics
                if len(mba.variables) <= 3 and mba.complexity == MBAComplexity.SIMPLE:
                    method = "truth_table"
                elif mba.complexity == MBAComplexity.SIMPLE:
                    method = "patterns"
                else:
                    method = "z3"
            
            # Apply selected simplification method
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
                result.complexity_reduction = self._calculate_complexity_reduction(
                    expression, simplified
                )
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
                    # Handle complex patterns specially
                    continue
                
                # Apply regex substitution
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
            # Create Z3 variables
            z3_vars = {}
            for var in mba.variables:
                z3_vars[var] = z3.BitVec(var, mba.bit_width)
            
            # Parse expression to Z3 (simplified parsing)
            z3_expr = self._parse_expression_to_z3(mba.expression, z3_vars)
            
            if z3_expr is not None:
                # Simplify with Z3
                simplified_z3 = z3.simplify(z3_expr)
                
                # Convert back to string
                simplified_str = str(simplified_z3)
                
                # Clean up Z3 formatting
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
            
            # Handle simple binary operations
            for op in ['+', '-', '*', '&', '|', '^']:
                if op in expression:
                    parts = expression.split(op, 1)
                    if len(parts) == 2:
                        left = parts[0].strip()
                        right = parts[1].strip()
                        
                        # Recursively parse operands
                        left_z3 = self._parse_operand_to_z3(left, z3_vars)
                        right_z3 = self._parse_operand_to_z3(right, z3_vars)
                        
                        if left_z3 is not None and right_z3 is not None:
                            if op == '+':
                                return left_z3 + right_z3
                            elif op == '-':
                                return left_z3 - right_z3
                            elif op == '*':
                                return left_z3 * right_z3
                            elif op == '&':
                                return left_z3 & right_z3
                            elif op == '|':
                                return left_z3 | right_z3
                            elif op == '^':
                                return left_z3 ^ right_z3
            
            # Single operand
            return self._parse_operand_to_z3(expression, z3_vars)
        
        except Exception as e:
            logger.debug(f"Z3 parsing error: {e}")
            return None
    
    def _parse_operand_to_z3(self, operand: str, z3_vars: dict[str, Any]) -> Any | None:
        """Parse single operand to Z3."""
        operand = operand.strip()
        
        # Check if it's a variable
        if operand in z3_vars:
            return z3_vars[operand]
        
        # Check if it's a number
        try:
            num = int(operand)
            return z3.BitVecVal(num, 64)
        except ValueError:
            pass
        
        return None
    
    def _cleanup_z3_output(self, z3_output: str) -> str:
        """Clean up Z3 output formatting."""
        # Remove Z3-specific formatting
        cleaned = z3_output.replace("BitVecRef", "").replace("BitVecVal", "")
        
        # Simplify bit vector operations
        cleaned = re.sub(r'\b(\w+)#64\b', r'\1', cleaned)
        
        return cleaned.strip()
    
    def _simplify_with_truth_table(self, mba: MBAExpression) -> str | None:
        """Simplify using truth table analysis (for small expressions)."""
        if len(mba.variables) > self.max_variables:
            return None
        
        try:
            # Generate truth table for all variable combinations
            variables = list(mba.variables)
            n_vars = len(variables)
            
            if n_vars == 0:
                return None
            
            # Evaluate expression for all input combinations
            truth_table = {}
            
            for i in range(2 ** n_vars):
                # Create variable assignment
                assignment = {}
                for j, var in enumerate(variables):
                    assignment[var] = (i >> j) & 1
                
                # Evaluate expression
                try:
                    result = self._evaluate_expression(mba.expression, assignment)
                    truth_table[tuple(assignment[var] for var in variables)] = result
                except Exception as e:
                    logger.debug(f"Expression evaluation failed: {e}")
                    return None
            
            # Try to find a simpler equivalent expression
            simplified = self._find_simple_equivalent(truth_table, variables)
            return simplified
        
        except Exception as e:
            logger.debug(f"Truth table simplification error: {e}")
            return None
    
    def _evaluate_expression(self, expression: str, assignment: dict[str, int]) -> int:
        """Evaluate expression with given variable assignment."""
        # Replace variables with their values
        expr = expression
        for var, value in assignment.items():
            expr = expr.replace(var, str(value))
        
        # Evaluate (dangerous - in production would need safe evaluation)
        try:
            # Simple evaluation for basic operators
            expr = expr.replace('&', ' & ').replace('|', ' | ').replace('^', ' ^ ')
            return eval(expr)
        except Exception as e:
            logger.debug(f"Failed to evaluate expression '{expr}': {e}")
            return 0
    
    def _find_simple_equivalent(self, truth_table: dict[tuple, int], variables: list[str]) -> str | None:
        """Find simple equivalent expression from truth table."""
        # Try simple patterns first
        
        # Check if always 0 or 1
        values = list(truth_table.values())
        if all(v == 0 for v in values):
            return "0"
        if all(v == 1 for v in values):
            return "1"
        
        # Check if equals one of the variables
        for i, var in enumerate(variables):
            if all(truth_table[inputs] == inputs[i] for inputs in truth_table):
                return var
        
        # Check simple operations between first two variables
        if len(variables) >= 2:
            var1, var2 = variables[0], variables[1]
            
            # Check XOR
            xor_match = all(
                truth_table[inputs] == (inputs[0] ^ inputs[1])
                for inputs in truth_table
            )
            if xor_match:
                return f"{var1} ^ {var2}"
            
            # Check AND
            and_match = all(
                truth_table[inputs] == (inputs[0] & inputs[1])
                for inputs in truth_table
            )
            if and_match:
                return f"{var1} & {var2}"
            
            # Check OR
            or_match = all(
                truth_table[inputs] == (inputs[0] | inputs[1])
                for inputs in truth_table
            )
            if or_match:
                return f"{var1} | {var2}"
        
        return None
    
    def _calculate_complexity_reduction(self, original: str, simplified: str) -> float:
        """Calculate complexity reduction percentage."""
        original_complexity = len(original) + original.count('(') * 2
        simplified_complexity = len(simplified) + simplified.count('(') * 2
        
        if original_complexity == 0:
            return 0.0
        
        reduction = (original_complexity - simplified_complexity) / original_complexity
        return max(0.0, reduction)
    
    def _generate_native_equivalent(self, simplified_expr: str) -> str | None:
        """Generate equivalent native assembly code."""
        # Map simple expressions to assembly
        if simplified_expr == "0":
            return "xor eax, eax"
        elif simplified_expr == "1":
            return "mov eax, 1"
        elif "^" in simplified_expr:
            return "xor eax, ebx"
        elif "&" in simplified_expr:
            return "and eax, ebx"
        elif "|" in simplified_expr:
            return "or eax, ebx"
        elif "+" in simplified_expr:
            return "add eax, ebx"
        elif "-" in simplified_expr:
            return "sub eax, ebx"
        
        return None
    
    def get_solver_statistics(self) -> dict[str, Any]:
        """Get solver performance statistics."""
        total = self.stats["expressions_analyzed"]
        
        stats = self.stats.copy()
        if total > 0:
            stats["success_rate"] = self.stats["expressions_simplified"] / total
            stats["pattern_success_rate"] = self.stats["pattern_matches"] / total
        else:
            stats["success_rate"] = 0.0
            stats["pattern_success_rate"] = 0.0
        
        return stats

