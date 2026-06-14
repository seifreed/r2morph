"""Pure equivalence helpers for Syntia semantic learning."""

from __future__ import annotations

import random
import re


def normalize_expression(expression: str) -> str:
    """Normalize an expression for comparison."""
    expr = expression.lower().strip()
    expr = re.sub(r"\s+", "", expr)
    expr = re.sub(r"\b0x([0-9a-f]+)\b", lambda m: str(int(m.group(1), 16)), expr)
    return expr


def check_mba_equivalence(expr1: str, expr2: str) -> float:
    """Check if expressions are known MBA equivalents."""
    mba_equivalences = [
        (("x+~x", "~x+x"), ("-1",)),
        (("x^1", "~x"), ()),
        (("x&x", "x"), ()),
        (("x|x", "x"), ()),
        (("x+(y&1)", "x+(y&1)"), ()),
    ]

    for equiv_group, _ in mba_equivalences:
        if expr1 in equiv_group and expr2 in equiv_group:
            return 0.9

    return 0.0


def synthesis_equivalence_check(expr1: str, expr2: str, variables: set[str], evaluator) -> float:
    """Use synthesis-style random sampling to check expression equivalence."""
    test_count = 10
    matches = 0

    for _ in range(test_count):
        test_values = {var: random.randint(0, 0xFFFF) for var in variables}

        try:
            val1 = evaluator(expr1, test_values)
            val2 = evaluator(expr2, test_values)
            if val1 == val2:
                matches += 1
        except Exception:
            continue

    return matches / test_count if test_count > 0 else 0.0
