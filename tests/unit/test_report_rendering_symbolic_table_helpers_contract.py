from r2morph.reporting.report_rendering_symbolic_table_helpers import (
    build_pass_evidence_rows,
    build_symbolic_coverage_rows,
    build_symbolic_issue_rows,
    build_symbolic_severity_rows,
)


def test_build_symbolic_coverage_rows_prefers_summary_rows() -> None:
    rows = build_symbolic_coverage_rows(
        summary={
            "symbolic_coverage_by_pass": [
                {
                    "pass_name": "alpha",
                    "observable_match": 1,
                    "observable_mismatch": 2,
                    "bounded_only": 3,
                    "without_coverage": 4,
                }
            ]
        },
        pass_results={},
        by_pass={},
    )

    assert rows == [
        {
            "pass_name": "alpha",
            "observable_match": 1,
            "observable_mismatch": 2,
            "bounded_only": 3,
            "without_coverage": 4,
        }
    ]


def test_build_symbolic_issue_rows_falls_back_to_pass_evidence() -> None:
    rows = build_symbolic_issue_rows(
        summary={
            "pass_evidence": [
                {
                    "pass_name": "alpha",
                    "symbolic_binary_mismatched_regions": 2,
                    "without_coverage": 1,
                    "bounded_only": 0,
                },
                {
                    "pass_name": "beta",
                    "symbolic_binary_mismatched_regions": 0,
                    "without_coverage": 0,
                    "bounded_only": 0,
                },
            ]
        },
        by_pass={},
    )

    assert rows == [
        {
            "pass_name": "alpha",
            "severity": "mismatch",
            "observable_mismatch": 2,
            "without_coverage": 1,
            "bounded_only": 0,
        }
    ]


def test_build_symbolic_severity_rows_uses_issue_and_coverage_fallbacks() -> None:
    rows = build_symbolic_severity_rows(
        summary={},
        by_pass={
            "alpha": {
                "symbolic_requested": 1,
                "observable_mismatch": 2,
                "without_coverage": 0,
                "bounded_only": 0,
            }
        },
        coverage_rows=[{"pass_name": "alpha", "issue_count": 0, "symbolic_requested": 1}],
        issue_rows=[{"pass_name": "alpha", "severity": "mismatch"}],
    )

    assert rows == [
        {
            "pass_name": "alpha",
            "severity": "mismatch",
            "issue_count": 0,
            "symbolic_requested": 1,
        }
    ]


def test_build_pass_evidence_rows_prefers_priority_rows() -> None:
    rows = build_pass_evidence_rows(
        summary={
            "pass_evidence_priority": [
                {
                    "pass_name": "alpha",
                    "changed_region_count": 1,
                    "structural_issue_count": 2,
                    "symbolic_binary_regions_checked": 3,
                    "symbolic_binary_mismatched_regions": 4,
                }
            ]
        },
        pass_results={},
    )

    assert rows == [
        {
            "pass_name": "alpha",
            "changed_region_count": 1,
            "structural_issue_count": 2,
            "symbolic_binary_regions_checked": 3,
            "symbolic_binary_mismatched_regions": 4,
        }
    ]
