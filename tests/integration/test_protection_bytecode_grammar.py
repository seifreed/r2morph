"""Regression coverage for per-instance bytecode grammar variation."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.protection_bytecode_grammar import measure
from tests.utils.assertions import expect

_REPORT = Path(__file__).resolve().parents[2] / "docs" / "protection-bytecode-grammar.json"
_EXPECTED_SCHEMA_VERSION = 2
_EXPECTED_SEED_COUNT = 10
_EXPECTED_ALL_HANDLER_STRIDE_UNIQUE_COUNT = 12
_EXPECTED_TARGET_STRIDE_UNIQUE_COUNT = 3


def test_measure_bytecode_grammar_varies_same_operation_stride_across_seeds() -> None:
    result = measure(20260820, 10)

    expect(
        result["schema_version"] == _EXPECTED_SCHEMA_VERSION
        and result["seeds_with_target_handlers"] == _EXPECTED_SEED_COUNT
        and result["seeds_without_target_handlers"] == 0
        and result["all_handler_stride_unique_count"] == _EXPECTED_ALL_HANDLER_STRIDE_UNIQUE_COUNT
        and result["target_stride_values"] == [3, 4, 5]
        and result["target_stride_unique_count"] == _EXPECTED_TARGET_STRIDE_UNIQUE_COUNT
        and result["target_stride_diverse"] is True
    )


def test_bytecode_grammar_report_matches_current_measurement() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(report == measure(20260820, 10))
