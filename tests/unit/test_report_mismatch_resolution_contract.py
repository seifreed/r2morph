from __future__ import annotations

from r2morph.reporting.report_mismatch_resolution import (
    _merge_mismatch_observables_from_mutations,
    _resolve_mismatch_view_from_summary,
)
from r2morph.reporting.report_state import resolve_mismatch_view


def test_resolve_mismatch_view_from_summary_uses_persisted_state_first() -> None:
    summary = {
        "report_views": {
            "only_mismatches": {
                "by_pass": {
                    "alpha": {
                        "mismatch_count": 2,
                        "observables": ["stack", "memory"],
                    }
                },
                "priority": [{"pass_name": "alpha", "mismatch_count": 2}],
                "rows": [{"pass_name": "alpha", "observables": ["stack", "memory"]}],
            }
        }
    }

    counts_by_pass, observables_by_pass, mismatch_priority, mismatch_view = _resolve_mismatch_view_from_summary(summary)

    assert counts_by_pass == {"alpha": 2}
    assert observables_by_pass == {"alpha": ["stack", "memory"]}
    assert mismatch_priority == [{"pass_name": "alpha", "mismatch_count": 2}]
    assert mismatch_view == [{"pass_name": "alpha", "observables": ["stack", "memory"]}]


def test_merge_mismatch_observables_from_mutations_accumulates_counts_and_observables() -> None:
    counts_by_pass = {"alpha": 2}
    observables_by_pass = {"alpha": ["stack", "memory"]}
    mutations = [
        {
            "pass_name": "alpha",
            "metadata": {"symbolic_observable_mismatches": ["memory", "register"]},
        },
        {
            "pass_name": "beta",
            "metadata": {"symbolic_observable_mismatches": []},
        },
    ]

    merged_counts, merged_observables = _merge_mismatch_observables_from_mutations(
        counts_by_pass,
        observables_by_pass,
        mutations,
    )

    assert merged_counts == {"alpha": 3, "beta": 1}
    assert merged_observables == {"alpha": ["memory", "register", "stack"]}


def test_report_state_wrapper_matches_helper_contract() -> None:
    summary = {
        "report_views": {
            "mismatch_map": {
                "alpha": {
                    "mismatch_count": 1,
                    "observables": ["memory"],
                }
            },
            "mismatch_priority": [{"pass_name": "alpha", "mismatch_count": 1}],
        }
    }
    mutations = [
        {
            "pass_name": "alpha",
            "metadata": {"symbolic_observable_mismatches": ["register"]},
        }
    ]

    assert resolve_mismatch_view(summary=summary, mutations=mutations) == (
        {"alpha": 2},
        {"alpha": ["memory", "register"]},
        [{"pass_name": "alpha", "mismatch_count": 1}],
    )
