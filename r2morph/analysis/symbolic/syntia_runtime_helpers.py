"""Pure runtime helpers for Syntia integration."""

from __future__ import annotations

import ast
import re
from typing import Any

from r2morph.core.safe_eval import safe_eval_arithmetic_node


def apply_mba_simplification_rules(expression: str, variables: set[str]) -> str | None:
    """Apply known MBA simplification rules."""

    expr_lower = expression.lower().replace(" ", "")

    patterns = [
        (r"(\w+)\s*\^\s*\1\b", "0"),
        (r"(\w+)\s*\|\s*0\b", r"\1"),
        (r"(\w+)\s*&\s*0\b", "0"),
        (r"(\w+)\s*\^\s*0\b", r"\1"),
        (r"(\w+)\s*&\s*~0\b", r"\1"),
        (r"(\w+)\s*\|\s*~0\b", "~0"),
        (r"(\w+)\s*&\s*\1\b", r"\1"),
        (r"(\w+)\s*\|\s*\1\b", r"\1"),
        (r"~~(\w+)", r"\1"),
    ]

    simplified = expr_lower
    for pattern, replacement in patterns:
        simplified = re.sub(pattern, replacement, simplified)

    if simplified != expr_lower:
        return simplified

    return None


def evaluate_expression(expression: str, values: dict[str, int]) -> int | None:
    """Safely evaluate an expression with given variable values."""

    expr = expression.lower()

    for var, val in values.items():
        expr = expr.replace(var.lower(), str(val))

    safe_chars = set("0123456789+-*&|^~() ")
    if not all(c in safe_chars for c in expr):
        return None

    try:
        tree = ast.parse(expr, mode="eval")
        result = safe_eval_arithmetic_node(tree.body)
        return int(result) & 0xFFFFFFFF
    except Exception:
        return None


def synthesize_obfuscated_sequence(
    input_registers: list[str], output_registers: list[str], target_semantics: str
) -> list[str] | None:
    """Synthesize a small instruction sequence for the target semantics."""

    synthesized = []
    semantic_lower = target_semantics.lower()

    if "add" in semantic_lower or "arithmetic" in semantic_lower:
        if input_registers and output_registers:
            synthesized.append(f"mov {output_registers[0]}, {input_registers[0]}")
            if len(input_registers) > 1:
                synthesized.append(f"add {output_registers[0]}, {input_registers[1]}")
    elif "xor" in semantic_lower or "logic" in semantic_lower:
        if input_registers and output_registers:
            synthesized.append(f"mov {output_registers[0]}, {input_registers[0]}")
            if len(input_registers) > 1:
                synthesized.append(f"xor {output_registers[0]}, {input_registers[1]}")
    elif "mov" in semantic_lower or "move" in semantic_lower:
        if input_registers and output_registers:
            synthesized.append(f"mov {output_registers[0]}, {input_registers[0]}")

    return synthesized if synthesized else None


def analyze_syntia_state(
    *,
    instructions_analyzed: int,
    semantics_learned: int,
    synthesis_failures: int,
    cache_hits: int,
    cache_size: int,
) -> dict[str, Any]:
    """Summarize Syntia runtime statistics."""
    stats: dict[str, Any] = {
        "instructions_analyzed": instructions_analyzed,
        "semantics_learned": semantics_learned,
        "synthesis_failures": synthesis_failures,
        "cache_hits": cache_hits,
        "cache_size": cache_size,
    }
    if instructions_analyzed > 0:
        stats["success_rate"] = semantics_learned / instructions_analyzed
        stats["cache_hit_rate"] = cache_hits / instructions_analyzed
    else:
        stats["success_rate"] = 0.0
        stats["cache_hit_rate"] = 0.0
    return stats
