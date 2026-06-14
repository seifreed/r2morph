"""Contract tests for report mutation selection helpers."""

from __future__ import annotations

from r2morph.reporting import report_helpers as helpers_mod
from r2morph.reporting.report_filters import ReportFilters
from r2morph.reporting.report_mutation_selection import _select_report_mutations


def test_select_report_mutations_filters_and_trims_degraded_rows() -> None:
    mutations = [
        {
            "pass_name": "risky-pass",
            "metadata": {"symbolic_status": "mismatch"},
        },
        {
            "pass_name": "clean-pass",
            "metadata": {"symbolic_status": "clean"},
        },
    ]
    degraded_passes = [
        {"pass_name": "risky-pass", "mutation": "risky-pass"},
        {"pass_name": "other-pass", "mutation": "other-pass"},
    ]

    expected = (
        [
            {
                "pass_name": "risky-pass",
                "metadata": {"symbolic_status": "mismatch"},
            }
        ],
        [{"pass_name": "risky-pass", "mutation": "risky-pass"}],
    )

    assert _select_report_mutations(
        all_mutations=mutations,
        degraded_validation=True,
        failed_gates=True,
        only_degraded=False,
        only_failed_gates=False,
        only_risky_filters=True,
        selected_risk_pass_names={"risky-pass"},
        resolved_only_pass="risky-pass",
        only_status="mismatch",
        degraded_passes=degraded_passes,
    ) == expected

    assert helpers_mod._select_report_mutations is _select_report_mutations

    assert ReportFilters.select_report_mutations(
        all_mutations=mutations,
        degraded_validation=True,
        failed_gates=True,
        only_degraded=False,
        only_failed_gates=False,
        only_risky_filters=True,
        selected_risk_pass_names={"risky-pass"},
        resolved_only_pass="risky-pass",
        only_status="mismatch",
        degraded_passes=degraded_passes,
    ) == expected
