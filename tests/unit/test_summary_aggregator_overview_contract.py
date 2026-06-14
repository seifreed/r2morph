from r2morph.reporting.summary_aggregator_overview import (
    summarize_degradation_roles,
    summarize_pass_timings,
)


def test_summarize_degradation_roles_counts_roles() -> None:
    assert summarize_degradation_roles(
        {
            "nop": {"validation_context": {"role": "baseline"}},
            "expand": {"validation_context": {"role": "degradation-trigger"}},
            "register": {"validation_context": {"role": "degradation-trigger"}},
            "block": {"validation_context": {}},
        }
    ) == {
        "baseline": 1,
        "degradation-trigger": 2,
    }


def test_summarize_pass_timings_orders_by_duration_then_name() -> None:
    rows = summarize_pass_timings(
        {
            "expand": {
                "execution_time_seconds": 2.5,
                "mutations": [1, 2],
                "rolled_back": False,
                "validation": {"issues": [1]},
            },
            "nop": {
                "execution_time_seconds": 2.5,
                "mutations": [1],
                "rolled_back": True,
                "validation": {"issues": []},
            },
            "register": {
                "execution_time_seconds": 1.0,
                "mutations": [],
                "rolled_back": False,
                "validation": {},
            },
        }
    )

    assert rows == [
        {
            "pass_name": "expand",
            "execution_time_seconds": 2.5,
            "mutations": 2,
            "rolled_back": False,
            "validation_issue_count": 1,
        },
        {
            "pass_name": "nop",
            "execution_time_seconds": 2.5,
            "mutations": 1,
            "rolled_back": True,
            "validation_issue_count": 0,
        },
        {
            "pass_name": "register",
            "execution_time_seconds": 1.0,
            "mutations": 0,
            "rolled_back": False,
            "validation_issue_count": 0,
        },
    ]

