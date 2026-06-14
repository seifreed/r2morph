from __future__ import annotations

from r2morph.reporting.report_helpers_classification import _has_structural_risk


def test_has_structural_risk_accepts_report_state_fallback_signature() -> None:
    assert _has_structural_risk({"structural_issue_count": 1}, {"severity": "clean"}) is True
    assert _has_structural_risk({"structural_issue_count": 0}, None) is False
