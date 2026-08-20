from __future__ import annotations

from r2morph.reporting.report_pass_classification import _has_structural_risk
from tests.utils.assertions import expect


def test_has_structural_risk_accepts_report_state_fallback_signature() -> None:
    expect(not (_has_structural_risk({"structural_issue_count": 1}, {"severity": "clean"}) is not True))
    expect(not (_has_structural_risk({"structural_issue_count": 0}, None) is not False))
