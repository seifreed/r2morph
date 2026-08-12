"""Contract tests for the canonical severity ranking."""

from __future__ import annotations

from r2morph.core import constants as core_constants
from r2morph.reporting import gate_evaluator


def test_severity_order_canonical_mapping() -> None:
    assert core_constants.SEVERITY_ORDER == {
        "mismatch": 0,
        "without-coverage": 1,
        "bounded-only": 2,
        "clean": 3,
        "not-requested": 4,
    }


def test_severity_order_is_a_single_shared_object() -> None:
    assert gate_evaluator.SEVERITY_ORDER is core_constants.SEVERITY_ORDER
