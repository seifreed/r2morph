from r2morph.reporting.report_rendering_summary_table_helpers import (
    build_summary_rows,
    build_validation_context_rows,
)


def test_build_summary_rows_skips_nested_values() -> None:
    rows = build_summary_rows(
        {
            "pass_count": 4,
            "nested": {"ignored": True},
            "items": ["ignored"],
            "label": "ok",
        }
    )

    assert rows == [("Pass Count", "4"), ("Label", "ok")]


def test_build_validation_context_rows_preserve_display_order() -> None:
    rows = build_validation_context_rows(
        [
            {"pass_name": "alpha", "validation_mode": "strict", "degraded_execution": True},
            {"pass_name": "beta", "validation_mode": "relaxed", "degraded_execution": False},
        ]
    )

    assert rows == [("alpha", "strict", "Yes"), ("beta", "relaxed", "No")]
