"""Property-based tests for report view projection helpers."""

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, strategies as st
from r2morph.reporting.report_view_builder import _project_rows, _build_category_views


@given(st.lists(st.dictionaries(st.text(min_size=1, max_size=10), st.text(max_size=20)), max_size=5))
def test_project_rows_preserves_length(rows):
    if not rows:
        return
    fields = list(rows[0].keys())[:3] if rows[0] else []
    result = _project_rows(rows, fields)
    assert len(result) == len(rows)


@given(st.lists(st.dictionaries(st.text(min_size=1, max_size=10), st.text(max_size=20)), max_size=5))
def test_project_rows_idempotent(rows):
    if not rows:
        return
    fields = list(rows[0].keys())[:3] if rows[0] else []
    first = _project_rows(rows, fields)
    second = _project_rows(first, fields)
    assert first == second


@given(
    st.lists(
        st.fixed_dictionaries({"pass_name": st.text(min_size=1, max_size=10), "count": st.integers(0, 100)}),
        max_size=5,
    )
)
def test_build_category_views_has_required_keys(rows):
    result = _build_category_views(rows, ["pass_name", "count"])
    assert "compact_by_pass" in result
    assert "compact_rows" in result
    assert "final_rows" in result
    assert "final_by_pass" in result
