from __future__ import annotations

from r2morph.reporting.report_pass_filters import resolve_pass_filter_sets


def test_resolve_pass_filter_sets_uses_persisted_views_and_fallbacks() -> None:
    summary = {
        "report_views": {
            "general_filter_views": {
                "only_risky_passes": ["risky-pass"],
                "only_clean_passes": ["clean-pass"],
            },
            "general_triage_rows": [
                {"pass_name": "triage-pass", "severity": "mismatch"},
            ],
        },
        "pass_risk_buckets": {},
        "pass_coverage_buckets": {},
        "pass_evidence": [{"pass_name": "fallback-pass", "structural_issue_count": 1}],
    }
    pass_results = {
        "fallback-pass": {
            "evidence_summary": {"structural_issue_count": 1},
            "symbolic_summary": {"severity": "clean", "issue_count": 0, "symbolic_requested": 0},
        }
    }

    result = resolve_pass_filter_sets(summary=summary, pass_results=pass_results)

    assert result["risky"] == {"risky-pass"}
    assert result["clean"] == {"clean-pass"}
    assert result["structural"] == {"fallback-pass"}
