from r2morph.core.report_helpers_symbolic_summary import (
    _build_symbolic_summary_for_pass,
    _summarize_symbolic_coverage_by_pass,
    _summarize_symbolic_issue_passes,
    _summarize_symbolic_overview,
    _summarize_symbolic_severity_by_pass,
    _summarize_symbolic_statuses,
)


def test_symbolic_issue_and_coverage_reducers() -> None:
    mutations = [
        {
            "pass_name": "nop",
            "metadata": {
                "symbolic_requested": True,
                "symbolic_observable_check_performed": True,
                "symbolic_observable_equivalent": False,
                "symbolic_status": "bounded-step-observable-mismatch",
            },
        },
        {
            "pass_name": "nop",
            "metadata": {
                "symbolic_requested": True,
                "symbolic_observable_check_performed": False,
                "symbolic_status": "bounded-step-passed",
            },
        },
        {
            "pass_name": "expand",
            "metadata": {
                "symbolic_requested": True,
                "symbolic_observable_check_performed": False,
                "symbolic_status": "runtime",
            },
        },
    ]

    assert _summarize_symbolic_issue_passes(mutations) == [
        {
            "pass_name": "nop",
            "severity": "mismatch",
            "observable_mismatch": 1,
            "without_coverage": 0,
            "bounded_only": 1,
        },
        {
            "pass_name": "expand",
            "severity": "without-coverage",
            "observable_mismatch": 0,
            "without_coverage": 1,
            "bounded_only": 0,
        },
    ]

    assert _summarize_symbolic_coverage_by_pass(mutations) == [
        {
            "pass_name": "nop",
            "symbolic_requested": 2,
            "observable_match": 0,
            "observable_mismatch": 1,
            "bounded_only": 1,
            "without_coverage": 0,
        },
        {
            "pass_name": "expand",
            "symbolic_requested": 1,
            "observable_match": 0,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 1,
        },
    ]


def test_symbolic_summary_and_overview_reducers() -> None:
    summary = _build_symbolic_summary_for_pass(
        "nop",
        [
            {
                "pass_name": "nop",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_observable_check_performed": True,
                    "symbolic_observable_equivalent": True,
                    "symbolic_status": "bounded-step-known-equivalence",
                },
            },
        ],
    )

    assert summary == {
        "pass_name": "nop",
        "symbolic_requested": 1,
        "observable_match": 1,
        "observable_mismatch": 0,
        "bounded_only": 0,
        "without_coverage": 0,
        "severity": "clean",
        "issue_count": 0,
        "issues": [],
    }

    global_counts, rows, mapping = _summarize_symbolic_statuses(
        [
            {"pass_name": "nop", "metadata": {"symbolic_status": "runtime"}},
            {"pass_name": "nop", "metadata": {"symbolic_status": "runtime"}},
            {"pass_name": "expand", "metadata": {"symbolic_status": "bounded-step-passed"}},
        ]
    )

    assert global_counts == {"runtime": 2, "bounded-step-passed": 1}
    assert rows == [
        {"pass_name": "nop", "statuses": {"runtime": 2}},
        {"pass_name": "expand", "statuses": {"bounded-step-passed": 1}},
    ]
    assert mapping == {"nop": {"runtime": 2}, "expand": {"bounded-step-passed": 1}}

    assert _summarize_symbolic_severity_by_pass({"nop": {"symbolic_summary": summary}}) == [
        {"pass_name": "nop", "severity": "clean", "issue_count": 0, "symbolic_requested": 1}
    ]

    assert _summarize_symbolic_overview(
        [{"symbolic_requested": 1, "observable_match": 1, "observable_mismatch": 0, "bounded_only": 0, "without_coverage": 0}],
        {"runtime": 2},
    ) == {
        "symbolic_requested": 1,
        "observable_match": 1,
        "observable_mismatch": 0,
        "bounded_only": 0,
        "without_coverage": 0,
        "statuses": {"runtime": 2},
    }

