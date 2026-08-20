"""Regression coverage for per-instance bytecode grammar variation."""

from __future__ import annotations

from scripts.protection_bytecode_grammar import measure


def test_measure_bytecode_grammar_varies_same_operation_stride_across_seeds() -> None:
    result = measure(20260820, 10)

    assert result["target_stride_values"] == [3, 4, 5]
