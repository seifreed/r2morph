from __future__ import annotations

from dataclasses import dataclass

from r2morph.reporting.report_context_mapping import (
    report_context_contains,
    report_context_get,
    report_context_getitem,
    report_context_items,
    report_context_iter,
    report_context_keys,
    report_context_to_dict,
    report_context_values,
)
from tests.utils.assertions import expect


@dataclass
class DummyContext:
    alpha: int = 1
    beta: str = "two"


def test_report_context_mapping_helpers_expose_dict_like_behavior() -> None:
    ctx = DummyContext()

    expect(report_context_getitem(ctx, "alpha") == 1)
    expect(not (report_context_contains(ctx, "beta") is not True))
    expect(report_context_get(ctx, "missing", "fallback") == "fallback")
    expect(report_context_keys(ctx) == ["alpha", "beta"])
    expect(report_context_values(ctx) == [1, "two"])
    expect(report_context_items(ctx) == [("alpha", 1), ("beta", "two")])
    expect(list(report_context_iter(ctx)) == ["alpha", "beta"])
    expect(report_context_to_dict(ctx) == {"alpha": 1, "beta": "two"})
