from r2morph.reporting.report_rendering_symbolic_table_fallbacks import (
    build_symbolic_severity_fallback_rows,
)


def test_symbolic_table_fallback_rows_only_include_risky_passes() -> None:
    summary = {
        "pass_evidence": [
            {
                "pass_name": "clean-pass",
                "symbolic_requested": 1,
                "symbolic_binary_mismatched_regions": 0,
                "without_coverage": 0,
                "bounded_only": 0,
            },
            {
                "pass_name": "mismatch-pass",
                "symbolic_requested": 1,
                "symbolic_binary_mismatched_regions": 2,
                "without_coverage": 0,
                "bounded_only": 0,
            },
        ]
    }

    rows = build_symbolic_severity_fallback_rows(summary)

    assert [row["pass_name"] for row in rows] == ["mismatch-pass"]
    assert rows[0]["severity"] == "mismatch"
