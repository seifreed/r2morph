"""SEVERITY_ORDER lives in core.constants; gate_evaluator re-exports it.

Characterizes the relocation contract (§7 layering): the canonical
definition is in the core layer and every historical import site keeps
resolving to the very same object, so the ranking cannot silently
diverge between layers.
"""

from __future__ import annotations

from r2morph.core import constants as core_constants
from r2morph.core import engine as core_engine
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
    assert core_engine.SEVERITY_ORDER is core_constants.SEVERITY_ORDER
