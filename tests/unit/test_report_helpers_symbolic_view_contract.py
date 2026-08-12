"""Lock the symbolic-view helper boundary."""

from __future__ import annotations

from r2morph.reporting import report_helpers_symbolic_view as symbolic_view_mod


def test_symbolic_view_helper_is_available_on_canonical_module() -> None:
    assert symbolic_view_mod._summarize_symbolic_view_from_mutations(summary={}, mutations=[]) == (
        0,
        0,
        0,
        0,
        0,
        {},
        [],
    )
