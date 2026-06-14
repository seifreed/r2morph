from r2morph.core.report_helpers_coverage import _summarize_pass_coverage_buckets


def test_summarize_pass_coverage_buckets_separates_clean_passes() -> None:
    buckets = _summarize_pass_coverage_buckets(
        {
            "covered": {
                "evidence_summary": {
                    "structural_issue_count": 0,
                    "symbolic_binary_mismatched_regions": 0,
                    "symbolic_binary_regions_checked": 2,
                },
                "symbolic_summary": {
                    "severity": "clean",
                    "issue_count": 0,
                    "symbolic_requested": 1,
                    "without_coverage": 0,
                },
            },
            "uncovered": {
                "evidence_summary": {
                    "structural_issue_count": 0,
                    "symbolic_binary_mismatched_regions": 0,
                    "symbolic_binary_regions_checked": 0,
                },
                "symbolic_summary": {
                    "severity": "not-requested",
                    "issue_count": 0,
                    "symbolic_requested": 0,
                    "without_coverage": 0,
                },
            },
            "risky": {
                "evidence_summary": {
                    "structural_issue_count": 1,
                    "symbolic_binary_mismatched_regions": 0,
                    "symbolic_binary_regions_checked": 1,
                },
                "symbolic_summary": {
                    "severity": "clean",
                    "issue_count": 0,
                    "symbolic_requested": 1,
                    "without_coverage": 0,
                },
            },
        }
    )

    assert buckets == {
        "covered": ["covered"],
        "uncovered": ["uncovered"],
        "clean_only": ["covered", "uncovered"],
    }
