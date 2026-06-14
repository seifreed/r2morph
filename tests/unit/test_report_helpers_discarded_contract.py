from r2morph.core import report_helpers as helpers_mod
from r2morph.core import report_helpers_discarded as discarded_mod
from r2morph.core import report_helpers_evidence as evidence_mod


def test_discarded_mutation_summaries_and_priority() -> None:
    summary = discarded_mod._summarize_discarded_mutations(
        [
            {"pass_name": "nop", "discard_reason": "rollback"},
            {"pass_name": "nop", "discard_reason": "skip_invalid_pass"},
            {"pass_name": "expand", "discard_reason": "validation_failed"},
            {"pass_name": "expand", "discard_reason": "rollback"},
        ]
    )

    assert summary == {
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

    assert discarded_mod._build_discarded_mutation_priority(summary) == [
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
    ]

    assert getattr(helpers_mod, "_summarize_discarded_mutations") is discarded_mod._summarize_discarded_mutations
    assert getattr(helpers_mod, "_build_discarded_mutation_priority") is discarded_mod._build_discarded_mutation_priority
    assert getattr(evidence_mod, "_summarize_discarded_mutations") is discarded_mod._summarize_discarded_mutations
    assert getattr(evidence_mod, "_build_discarded_mutation_priority") is discarded_mod._build_discarded_mutation_priority
