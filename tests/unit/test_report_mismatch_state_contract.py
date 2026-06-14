from __future__ import annotations

from r2morph.reporting.report_mismatch_state import resolve_only_mismatches_state


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
        resolved_only_pass=None,
        degraded_passes=[{"pass_name": "persisted-pass", "mutation": "persisted-pass"}],
    )

    assert len(result["filtered_mutations"]) == 1
    assert result["filtered_passes"] == ["persisted-pass"]
    assert result["mismatch_pass_context"] == {"persisted-pass": {"severity": "mismatch"}}
    assert result["mismatch_severity_rows"][0]["pass_name"] == "persisted-pass"
