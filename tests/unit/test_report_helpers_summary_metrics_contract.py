from r2morph.core.report_helpers_summary_metrics import (
    _summarize_diff_digest,
    _summarize_pass_timings,
)


def test_summarize_pass_timings_orders_by_duration_then_name() -> None:
    rows = _summarize_pass_timings(
        {
            "slow": {
                "execution_time_seconds": 0.5,
                "mutations": [1, 2],
                "rolled_back": False,
                "validation": {"issues": [{}]},
            },
            "fast": {
                "execution_time_seconds": 0.1,
                "mutations": [],
                "rolled_back": True,
                "validation": {"issues": []},
            },
        }
    )

    assert rows == [
        {
            "pass_name": "slow",
            "execution_time_seconds": 0.5,
            "mutations": 2,
            "rolled_back": False,
            "validation_issue_count": 1,
        },
        {
            "pass_name": "fast",
            "execution_time_seconds": 0.1,
            "mutations": 0,
            "rolled_back": True,
            "validation_issue_count": 0,
        },
    ]


def test_summarize_diff_digest_orders_passes_by_change_weight() -> None:
    digest = _summarize_diff_digest(
        {
            "noop": {"diff_summary": {"changed_regions": [], "changed_bytes": 0, "mutation_kinds": []}},
            "patch": {
                "diff_summary": {
                    "changed_regions": [[1, 2]],
                    "changed_bytes": 2,
                    "mutation_kinds": ["instruction_substitution"],
                }
            },
            "bigger": {
                "diff_summary": {
                    "changed_regions": [[1, 2], [3, 4]],
                    "changed_bytes": 4,
                    "mutation_kinds": ["nop_insertion"],
                }
            },
        }
    )

    assert digest == {
        "changed_region_count": 3,
        "changed_bytes": 6,
        "mutation_kinds": ["instruction_substitution", "nop_insertion"],
        "passes_with_changes": [
            {
                "pass_name": "bigger",
                "changed_region_count": 2,
                "changed_bytes": 4,
            },
            {
                "pass_name": "patch",
                "changed_region_count": 1,
                "changed_bytes": 2,
            },
        ],
    }
