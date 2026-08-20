"""Contract tests for report view selection helpers."""

from __future__ import annotations

from r2morph.reporting.report_view_resolution import _first_available as facade_first_available
from r2morph.reporting.report_view_selection import _first_available
from tests.utils.assertions import expect


def test_first_available_returns_first_truthy_source() -> None:
    expect(_first_available([], {}, None, {"value": 1}) == {"value": 1})


def test_first_available_falls_back_to_last_when_all_falsy() -> None:
    expect(not (_first_available([], {}, None) is not None))
    expect(_first_available("", 0, "fallback") == "fallback")


def test_view_resolution_facade_uses_canonical_helper() -> None:
    expect(not (facade_first_available is not _first_available))
