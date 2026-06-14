"""Pure helper functions for MBA analysis and simplification."""

from __future__ import annotations

import ast
import re

from r2morph.core.safe_eval import safe_eval_arithmetic_node


def load_mba_patterns() -> dict[str, str]:
    """Load known MBA patterns and their simplified forms."""
    return {
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


def extract_variables(expression: str) -> set[str]:
    """Extract variable names from expression."""
    var_pattern = r"\b[a-zA-Z][a-zA-Z0-9_]*\b"
    potential_vars = re.findall(var_pattern, expression)

    operators = {"and", "or", "xor", "not", "shl", "shr", "add", "sub", "mul", "div"}
    variables = set()

    for var in potential_vars:
        if var.lower() not in operators and not var.isdigit():
            variables.add(var)

    return variables


def calculate_parentheses_depth(expression: str) -> int:
    """Calculate maximum parentheses nesting depth."""
    max_depth = 0
    current_depth = 0

    for char in expression:
        if char == "(":
            current_depth += 1
            max_depth = max(max_depth, current_depth)
        elif char == ")":
            current_depth -= 1

    return max_depth


def assess_complexity(expression: str) -> str:
    """Assess the complexity of an MBA expression."""
    op_count = sum(expression.count(op) for op in ["+", "-", "*", "/", "&", "|", "^", "~"])
    paren_depth = calculate_parentheses_depth(expression)

    if op_count <= 3 and paren_depth <= 2:
        return "simple"
    if op_count <= 10 and paren_depth <= 4:
        return "medium"
    return "complex"


def is_linear_mba(expression: str) -> bool:
    """Check if expression is a linear MBA."""
    return "*" not in expression or not any(
        var1 + "*" + var2 in expression or var2 + "*" + var1 in expression
        for var1 in extract_variables(expression)
        for var2 in extract_variables(expression)
        if var1 != var2
    )


def calculate_polynomial_degree(expression: str) -> int:
    """Calculate polynomial degree (simplified estimation)."""
    max_degree = 1
    mult_parts = expression.split("*")
    for part in mult_parts:
        var_count = len(extract_variables(part))
        max_degree = max(max_degree, var_count)

    return max_degree


def count_coefficients(expression: str) -> int:
    """Count numeric coefficients in expression."""
    number_pattern = r"\b\d+\b"
    numbers = re.findall(number_pattern, expression)
    return len(numbers)


def cleanup_z3_output(z3_output: str) -> str:
    """Clean up Z3 output formatting."""
    cleaned = z3_output.replace("BitVecRef", "").replace("BitVecVal", "")
    cleaned = re.sub(r"#\d+\b", "", cleaned)
    return cleaned.strip()


def evaluate_expression(expression: str, assignment: dict[str, int]) -> int:
    """Evaluate expression with given variable assignment using safe AST evaluation."""
    expr = expression
    for var, value in assignment.items():
        expr = expr.replace(var, str(value))

    expr = expr.replace("&", " & ").replace("|", " | ").replace("^", " ^ ")

    try:
        tree = ast.parse(expr, mode="eval")
        result = safe_eval_arithmetic_node(tree.body)
        return int(result)
    except Exception:
        return 0


def find_simple_equivalent(truth_table: dict[tuple, int], variables: list[str]) -> str | None:
    """Find simple equivalent expression from truth table."""
    values = list(truth_table.values())
    if all(v == 0 for v in values):
        return "0"
    if all(v == 1 for v in values):
        return "1"

    for i, var in enumerate(variables):
        if all(truth_table[inputs] == inputs[i] for inputs in truth_table):
            return var

    if len(variables) >= 2:
        var1, var2 = variables[0], variables[1]

        xor_match = all(truth_table[inputs] == (inputs[0] ^ inputs[1]) for inputs in truth_table)
        if xor_match:
            return f"{var1} ^ {var2}"

        and_match = all(truth_table[inputs] == (inputs[0] & inputs[1]) for inputs in truth_table)
        if and_match:
            return f"{var1} & {var2}"

        or_match = all(truth_table[inputs] == (inputs[0] | inputs[1]) for inputs in truth_table)
        if or_match:
            return f"{var1} | {var2}"

    return None


def calculate_complexity_reduction(original: str, simplified: str) -> float:
    """Calculate complexity reduction percentage."""
    original_complexity = len(original) + original.count("(") * 2
    simplified_complexity = len(simplified) + simplified.count("(") * 2

    if original_complexity == 0:
        return 0.0

    reduction = (original_complexity - simplified_complexity) / original_complexity
    return max(0.0, reduction)


def generate_native_equivalent(simplified_expr: str) -> str | None:
    """Generate equivalent native assembly code."""
    if simplified_expr == "0":
        return "xor eax, eax"
    if simplified_expr == "1":
        return "mov eax, 1"
    if "^" in simplified_expr:
        return "xor eax, ebx"
    if "&" in simplified_expr:
        return "and eax, ebx"
    if "|" in simplified_expr:
        return "or eax, ebx"
    if "+" in simplified_expr:
        return "add eax, ebx"
    if "-" in simplified_expr:
        return "sub eax, ebx"

    return None
