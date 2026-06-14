from r2morph.reporting.report_rendering_table_helpers import (
    build_degradation_role_rows,
    build_gate_failure_rows,
    build_mismatch_rows,
    build_symbolic_summary_rows,
)


def test_build_symbolic_summary_rows_returns_empty_when_not_requested() -> None:
    assert (
        build_symbolic_summary_rows(
            symbolic_requested=0,
            observable_match=1,
            observable_mismatch=2,
            bounded_only=3,
            without_coverage=4,
        )
        == []
    )


def test_build_gate_failure_rows_preserves_display_fields() -> None:
    rows = build_gate_failure_rows(
        [
            {
                "pass_name": "alpha",
                "failure_count": 3,
                "strictest_expected_severity": "high",
            }
        ]
    )

    assert rows == [("alpha", "3", "high")]


def test_build_degradation_role_rows_honors_disabled_flag() -> None:
    assert build_degradation_role_rows({"degraded_validation": False}) == []


def test_build_mismatch_rows_preserves_row_order() -> None:
    rows = build_mismatch_rows(
        [
            {"pass_name": "alpha", "mismatch_count": 2, "region_count": 5},
            {"pass_name": "beta", "mismatch_count": 1, "region_count": 3},
        ]
    )

    assert rows == [("alpha", "2", "5"), ("beta", "1", "3")]
