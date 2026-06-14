from r2morph.reporting.summary_aggregator_details import (
    summarize_diff_digest,
    summarize_discarded_mutations,
)


def test_summarize_diff_digest_orders_passes_by_change_weight() -> None:
    result = summarize_diff_digest(
        {
            "nop": {"diff_summary": {"changed_regions": [1], "changed_bytes": 4, "mutation_kinds": ["nop"]}},
            "expand": {"diff_summary": {"changed_regions": [1, 2], "changed_bytes": 2, "mutation_kinds": ["expand"]}},
            "register": {"diff_summary": {"changed_regions": [], "changed_bytes": 0, "mutation_kinds": ["register"]}},
        }
    )

    assert result == {
        "changed_region_count": 3,
        "changed_bytes": 6,
        "mutation_kinds": ["expand", "nop", "register"],
        "passes_with_changes": [
            {"pass_name": "nop", "changed_region_count": 1, "changed_bytes": 4},
            {"pass_name": "expand", "changed_region_count": 2, "changed_bytes": 2},
        ],
    }


def test_summarize_discarded_mutations_groups_by_pass_and_reason() -> None:
    result = summarize_discarded_mutations(
        [
            {"pass_name": "nop", "discard_reason": "rollback"},
            {"pass_name": "nop", "discard_reason": "skip_invalid_pass"},
            {"pass_name": "expand", "discard_reason": "validation_failed"},
            {"pass_name": "expand", "discard_reason": "rollback"},
        ]
    )

    assert result == {
        "by_pass": [
            {
                "pass_name": "expand",
                "discarded_count": 2,
                "impact_severity": "high",
                "reasons": {"rollback": 1, "validation_failed": 1},
            },
            {
                "pass_name": "nop",
                "discarded_count": 2,
                "impact_severity": "medium",
                "reasons": {"rollback": 1, "skip_invalid_pass": 1},
            },
        ],
        "by_reason": {"rollback": 2, "skip_invalid_pass": 1, "validation_failed": 1},
        "by_impact": {
            "high": [
                {
                    "pass_name": "expand",
                    "discarded_count": 2,
                    "impact_severity": "high",
                    "reasons": {"rollback": 1, "validation_failed": 1},
                }
            ],
            "medium": [
                {
                    "pass_name": "nop",
                    "discarded_count": 2,
                    "impact_severity": "medium",
                    "reasons": {"rollback": 1, "skip_invalid_pass": 1},
                }
            ],
            "low": [],
        },
        "by_pass_map": {
            "expand": {
                "discarded_count": 2,
                "impact_severity": "high",
                "reasons": {"rollback": 1, "validation_failed": 1},
            },
            "nop": {
                "discarded_count": 2,
                "impact_severity": "medium",
                "reasons": {"rollback": 1, "skip_invalid_pass": 1},
            },
        },
    }

