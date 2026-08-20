"""Contract tests for report mutation selection helpers."""

from __future__ import annotations

from r2morph.reporting.report_builder_models import ReportContext
from r2morph.reporting.report_context import FilterFlags
from r2morph.reporting.report_mutation_selection import _select_report_mutations
from tests.utils.assertions import expect
from tests.utils.field_names import RESOLVED_ONLY_FAILED_MUTATION_KEY, RESOLVED_ONLY_MUTATION_KEY


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

    context = ReportContext(
        summary={},
        **{RESOLVED_ONLY_MUTATION_KEY: "risky-pass"},
        **{RESOLVED_ONLY_FAILED_MUTATION_KEY: None},
        requested_validation_mode=None,
        effective_validation_mode=None,
        validation_policy=None,
        gate_evaluation={},
        gate_requested={},
        gate_results={},
        gate_failure_summary={},
        gate_failure_priority=[],
        gate_failure_severity_priority=[],
        failed_gates=True,
        degraded_validation=True,
        degraded_passes=degraded_passes,
        degradation_roles={},
    )
    filters = FilterFlags(only_status="mismatch", only_risky_passes=True)

    expect(_select_report_mutations(mutations, context, filters, {"risky-pass"}) == expected)
