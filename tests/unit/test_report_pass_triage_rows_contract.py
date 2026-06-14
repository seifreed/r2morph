from __future__ import annotations

from r2morph.reporting.report_pass_triage_rows import _pass_names_from_triage_rows


def test_pass_names_from_triage_rows_classifies_structural_and_risky_rows() -> None:
    triage_rows = [
        {"pass_name": "structural-pass", "structural_issue_count": 1},
        {
            "pass_name": "symbolic-pass",
            "severity": "mismatch",
            "symbolic_binary_mismatched_regions": 1,
        },
    ]

    assert _pass_names_from_triage_rows(triage_rows, kind="structural") == {"structural-pass"}
    assert _pass_names_from_triage_rows(triage_rows, kind="risky") == {"structural-pass", "symbolic-pass"}


def test_pass_names_from_triage_rows_classifies_clean_coverage_variants() -> None:
    triage_rows = [
        {
            "pass_name": "clean-pass",
            "severity": "clean",
            "symbolic_requested": 1,
            "without_coverage": 0,
        },
        {
            "pass_name": "uncovered-pass",
            "severity": "clean",
            "symbolic_requested": 1,
            "without_coverage": 1,
        },
    ]

    assert _pass_names_from_triage_rows(triage_rows, kind="clean") == {"clean-pass", "uncovered-pass"}
    assert _pass_names_from_triage_rows(triage_rows, kind="covered") == {"clean-pass"}
    assert _pass_names_from_triage_rows(triage_rows, kind="uncovered") == {"uncovered-pass"}
