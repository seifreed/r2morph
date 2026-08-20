from r2morph.reporting import summary_aggregator as aggregator_mod
from r2morph.reporting import summary_aggregator_symbolic as facade_mod
from r2morph.reporting import summary_aggregator_symbolic_metrics as metrics_mod
from tests.utils.assertions import expect


def test_symbolic_stats_and_aggregator_contract() -> None:
    stats = metrics_mod.SymbolicStats(symbolic_requested=2, observable_match=1)

    expect(
        stats.to_dict()
        == {
            "symbolic_requested": 2,
            "observable_match": 1,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 0,
        }
    )

    mutations = [
        {"pass_name": "nop", "metadata": {"symbolic_status": "runtime"}},
        {"pass_name": "nop", "metadata": {"symbolic_status": "runtime"}},
        {"pass_name": "expand", "metadata": {"symbolic_status": "bounded-step-passed"}},
    ]

    global_counts, rows, mapping = metrics_mod.SymbolicAggregator.summarize_from_mutations(mutations)
    expect(global_counts == {"runtime": 2, "bounded-step-passed": 1})
    expect(
        rows
        == [
            {"pass_name": "nop", "statuses": {"runtime": 2}},
            {"pass_name": "expand", "statuses": {"bounded-step-passed": 1}},
        ]
    )
    expect(mapping == {"nop": {"runtime": 2}, "expand": {"bounded-step-passed": 1}})

    expect(
        metrics_mod.SymbolicAggregator.summarize_coverage_by_pass(
            [
                {
                    "pass_name": "nop",
                    "metadata": {
                        "symbolic_requested": True,
                        "symbolic_observable_check_performed": True,
                        "symbolic_observable_equivalent": False,
                        "symbolic_status": "bounded-step-observable-mismatch",
                    },
                }
            ]
        )
        == [
            {
                "pass_name": "nop",
                "symbolic_requested": 1,
                "observable_match": 0,
                "observable_mismatch": 1,
                "bounded_only": 0,
                "without_coverage": 0,
            }
        ]
    )

    expect(
        metrics_mod.SymbolicAggregator.summarize_issue_passes(
            [
                {
                    "pass_name": "nop",
                    "metadata": {
                        "symbolic_requested": True,
                        "symbolic_observable_check_performed": True,
                        "symbolic_observable_equivalent": False,
                        "symbolic_status": "bounded-step-observable-mismatch",
                    },
                }
            ]
        )
        == [
            {
                "pass_name": "nop",
                "severity": "mismatch",
                "observable_mismatch": 1,
                "without_coverage": 0,
                "bounded_only": 0,
            }
        ]
    )

    expect(
        metrics_mod.SymbolicAggregator.summarize_observable_mismatches_by_pass(
            [
                {
                    "pass_name": "nop",
                    "metadata": {
                        "symbolic_observable_check_performed": True,
                        "symbolic_observable_equivalent": False,
                        "symbolic_observable_mismatches": ["cf"],
                    },
                }
            ]
        )
        == [{"pass_name": "nop", "mismatch_count": 1, "observables": ["cf"]}]
    )

    expect(not (aggregator_mod.SymbolicAggregator is not metrics_mod.SymbolicAggregator))
    expect(not (aggregator_mod.SymbolicStats is not metrics_mod.SymbolicStats))
    expect(not (facade_mod.SymbolicAggregator is not metrics_mod.SymbolicAggregator))
    expect(not (facade_mod.SymbolicStats is not metrics_mod.SymbolicStats))
