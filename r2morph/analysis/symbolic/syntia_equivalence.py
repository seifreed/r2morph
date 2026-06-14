"""Semantic equivalence helpers for Syntia integration."""

from __future__ import annotations

from collections.abc import Callable

from r2morph.analysis.symbolic.syntia_equivalence_helpers import (
    check_mba_equivalence,
    normalize_expression,
    synthesis_equivalence_check,
)


def check_semantic_equivalence(
    expr1: str,
    expr2: str,
    variables: set[str],
    evaluator: Callable[[str, dict[str, int]], int | None],
) -> float:
    """Check whether two expressions are semantically equivalent."""
    if expr1.strip() == expr2.strip():
        return 1.0

    expr1_normalized = normalize_expression(expr1)
    expr2_normalized = normalize_expression(expr2)

    if expr1_normalized == expr2_normalized:
        return 1.0

    equivalence_confidence = check_mba_equivalence(expr1_normalized, expr2_normalized)
    if equivalence_confidence > 0:
        return equivalence_confidence

    return synthesis_equivalence_check(expr1_normalized, expr2_normalized, variables, evaluator)
