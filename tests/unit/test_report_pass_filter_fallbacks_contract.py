from __future__ import annotations

from r2morph.reporting.report_pass_filter_fallbacks import _resolve_pass_filter_fallbacks
from tests.utils.assertions import expect


def test_resolve_pass_filter_fallbacks_uses_triage_rows_before_predicate_fallbacks() -> None:
    resolved = {
        "risky": set(),
        "structural": set(),
        "symbolic": set(),
        "clean": set(),
        "covered": set(),
        "uncovered": set(),
    }
    summary = {}
    pass_results = {
        "triage-pass": {"evidence_summary": {}, "symbolic_summary": {}},
    }

    result = _resolve_pass_filter_fallbacks(
        resolved=resolved,
        summary=summary,
        pass_results=pass_results,
        summary_pass_evidence=[],
        triage_rows=[{"pass_name": "triage-pass", "structural_issue_count": 1}],
    )

    expect(result["structural"] == {"triage-pass"})
    expect(result["risky"] == {"triage-pass"})
    expect(result["symbolic"] == set())
    expect(result["clean"] == {"triage-pass"})
    expect(result["covered"] == set())
    expect(result["uncovered"] == {"triage-pass"})


def test_resolve_pass_filter_fallbacks_uses_summary_evidence_when_needed() -> None:
    resolved = {
        "risky": set(),
        "structural": set(),
        "symbolic": set(),
        "clean": set(),
        "covered": set(),
        "uncovered": set(),
    }
    pass_results = {
        "fallback-pass": {
            "evidence_summary": {"structural_issue_count": 1},
            "symbolic_summary": {"severity": "clean", "issue_count": 0, "symbolic_requested": 0},
        }
    }

    result = _resolve_pass_filter_fallbacks(
        resolved=resolved,
        summary={},
        pass_results=pass_results,
        summary_pass_evidence=[{"pass_name": "fallback-pass", "structural_issue_count": 1}],
        triage_rows=[],
    )

    expect(result["structural"] == {"fallback-pass"})
