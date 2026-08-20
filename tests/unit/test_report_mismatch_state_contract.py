from __future__ import annotations

from r2morph.reporting.report_mismatch_state import resolve_only_mismatches_state
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY, RESOLVED_MUTATION_KEY


def test_resolve_only_mismatches_state_filters_runtime_mismatches_and_uses_persisted_fallback() -> None:
    summary = {
        "report_views": {"only_mismatches": {"compact_rows": [{"pass_name": "persisted-pass"}]}},
        "symbolic_severity_by_pass": [],
        "pass_symbolic_summary": {
            "persisted-pass": {
                "severity": "mismatch",
                "issue_count": 7,
                "symbolic_requested": 4,
            }
        },
    }
    mutations = [
        {
            "metadata": {
                "symbolic_observable_check_performed": True,
                "symbolic_observable_equivalent": False,
            }
        },
        {
            "metadata": {
                "symbolic_observable_check_performed": False,
                "symbolic_observable_equivalent": False,
            }
        },
    ]
    filtered_summary = {
        "pass_validation_context": {"persisted-pass": {"severity": "mismatch"}},
        "pass_symbolic_summary": {
            "persisted-pass": {
                "severity": "mismatch",
                "issue_count": 7,
                "symbolic_requested": 4,
            }
        },
    }

    result = resolve_only_mismatches_state(
        summary=summary,
        mutations=mutations,
        filtered_summary=filtered_summary,
        **{RESOLVED_MUTATION_KEY: None},
        degraded_passes=[{"pass_name": "persisted-pass", "mutation": "persisted-pass"}],
    )

    expect(len(result["filtered_mutations"]) == 1)
    expect(result["filtered_passes"] == ["persisted-pass"])
    expect(result["mismatch_pass_context"] == {"persisted-pass": {"severity": "mismatch"}})
    expect(result["mismatch_severity_rows"][0][MUTATION_NAME_KEY] == "persisted-pass")
