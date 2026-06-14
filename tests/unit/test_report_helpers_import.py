"""The report helpers moved to core.report_helpers; core.engine re-exports.

Locks the backward-compatibility contract: every helper (and
REPORT_SCHEMA_VERSION) stays importable from r2morph.core.engine and is
the *same object* as in r2morph.core.report_helpers, so the two import
sites can never silently diverge.
"""

from __future__ import annotations

from r2morph.core import engine as engine_mod
from r2morph.core import report_helpers as helpers_mod
from r2morph.core import report_helpers_adjustment as adjustment_mod
from r2morph.core import report_helpers_discarded as discarded_mod
from r2morph.core import report_helpers_evidence_summary as evidence_summary_mod
from r2morph.core import report_helpers_observables as observables_mod
from r2morph.core import report_helpers_projection as projection_mod
from r2morph.core import report_helpers_risk as risk_mod
from r2morph.core import report_helpers_symbolic_summary as symbolic_summary_mod
from r2morph.core import report_helpers_triage as triage_mod
from r2morph.reporting import report_evidence_sorting as evidence_sorting_mod
from r2morph.reporting import report_helpers_symbolic_view as symbolic_view_mod

REEXPORTED_NAMES = [
    "REPORT_SCHEMA_VERSION",
    "_build_discarded_mutation_priority",
    "_build_evidence_summary_for_pass",
    "_build_observable_mismatch_map",
    "_build_observable_mismatch_priority",
    "_build_symbolic_summary_for_pass",
    "_build_pass_triage_map",
    "_build_pass_validation_context",
    "_build_validation_role_map",
    "_enrich_validation_policy",
    "_summarize_degradation_roles",
    "_summarize_diff_digest",
    "_summarize_discarded_mutations",
    "_summarize_observable_mismatches_by_pass",
    "_summarize_pass_coverage_buckets",
    "_summarize_pass_evidence",
    "_summarize_pass_risk_buckets",
    "_summarize_pass_timings",
    "_summarize_structural_evidence",
    "_sort_pass_evidence",
    "_summarize_symbolic_coverage_by_pass",
    "_summarize_symbolic_issue_passes",
    "_summarize_symbolic_overview",
    "_summarize_symbolic_severity_by_pass",
    "_summarize_symbolic_statuses",
    "_summarize_symbolic_view_from_mutations",
    "_summarize_validation_role_rows",
]

PROJECTION_NAMES = [
    "_build_pass_capability_summary_map",
    "_build_pass_region_evidence_map",
    "_summarize_normalized_pass_results",
    "_summarize_pass_capability_rows",
]

OBSERVABLE_NAMES = [
    "_build_observable_mismatch_map",
    "_build_observable_mismatch_priority",
    "_summarize_observable_mismatches_by_pass",
]

ADJUSTMENT_NAMES = [
    "_summarize_validation_adjustment_rows",
    "_summarize_validation_adjustments",
]

RISK_NAMES = [
    "_summarize_pass_coverage_buckets",
    "_summarize_pass_risk_buckets",
]

TRIAGE_NAMES = [
    "_build_pass_triage_map",
    "_summarize_pass_evidence_compact",
    "_summarize_pass_triage_rows",
]


def test_canonical_module_defines_all_helpers() -> None:
    for name in REEXPORTED_NAMES:
        assert hasattr(helpers_mod, name), f"core.report_helpers missing {name}"


def test_canonical_triage_module_defines_triage_helpers() -> None:
    for name in TRIAGE_NAMES:
        assert hasattr(triage_mod, name), f"core.report_helpers_triage missing {name}"


def test_canonical_projection_module_defines_projection_helpers() -> None:
    for name in PROJECTION_NAMES:
        assert hasattr(projection_mod, name), f"core.report_helpers_projection missing {name}"


def test_canonical_observable_module_defines_observable_helpers() -> None:
    for name in OBSERVABLE_NAMES:
        assert hasattr(observables_mod, name), f"core.report_helpers_observables missing {name}"


def test_canonical_adjustment_module_defines_adjustment_helpers() -> None:
    for name in ADJUSTMENT_NAMES:
        assert hasattr(adjustment_mod, name), f"core.report_helpers_adjustment missing {name}"


def test_canonical_risk_module_defines_risk_helpers() -> None:
    for name in RISK_NAMES:
        assert hasattr(risk_mod, name), f"core.report_helpers_risk missing {name}"


def test_canonical_evidence_summary_module_defines_evidence_helpers() -> None:
    for name in ("_summarize_pass_evidence", "_build_pass_region_evidence_map"):
        assert hasattr(
            evidence_summary_mod,
            name,
        ), f"core.report_helpers_evidence_summary missing {name}"


def test_canonical_discarded_module_defines_discarded_helpers() -> None:
    for name in ("_summarize_discarded_mutations", "_build_discarded_mutation_priority"):
        assert hasattr(
            discarded_mod,
            name,
        ), f"core.report_helpers_discarded missing {name}"


def test_canonical_symbolic_summary_module_defines_symbolic_helpers() -> None:
    for name in (
        "_build_symbolic_summary_for_pass",
        "_summarize_symbolic_coverage_by_pass",
        "_summarize_symbolic_issue_passes",
        "_summarize_symbolic_overview",
        "_summarize_symbolic_severity_by_pass",
        "_summarize_symbolic_statuses",
    ):
        assert hasattr(
            symbolic_summary_mod,
            name,
        ), f"core.report_helpers_symbolic_summary missing {name}"


def test_canonical_symbolic_view_module_defines_symbolic_view_helpers() -> None:
    assert hasattr(
        symbolic_view_mod,
        "_summarize_symbolic_view_from_mutations",
    ), "report_helpers_symbolic_view missing _summarize_symbolic_view_from_mutations"


def test_canonical_evidence_sorting_module_defines_evidence_sorting_helper() -> None:
    assert hasattr(
        evidence_sorting_mod,
        "_sort_pass_evidence",
    ), "report_evidence_sorting missing _sort_pass_evidence"


def test_engine_reexports_are_the_same_objects() -> None:
    for name in REEXPORTED_NAMES:
        assert hasattr(engine_mod, name), f"core.engine no longer re-exports {name}"
        assert getattr(engine_mod, name) is getattr(
            helpers_mod, name
        ), f"core.engine.{name} diverged from core.report_helpers.{name}"


def test_triage_helpers_are_reexported_from_facade() -> None:
    for name in TRIAGE_NAMES:
        assert getattr(helpers_mod, name) is getattr(
            triage_mod, name
        ), f"core.report_helpers.{name} diverged from core.report_helpers_triage.{name}"
        assert hasattr(engine_mod, name), f"core.engine no longer re-exports {name}"
        assert getattr(engine_mod, name) is getattr(
            triage_mod, name
        ), f"core.engine.{name} diverged from core.report_helpers_triage.{name}"


def test_projection_helpers_are_reexported_from_facade() -> None:
    for name in PROJECTION_NAMES:
        assert getattr(helpers_mod, name) is getattr(
            projection_mod, name
        ), f"core.report_helpers.{name} diverged from core.report_helpers_projection.{name}"
        assert hasattr(engine_mod, name), f"core.engine no longer re-exports {name}"
        assert getattr(engine_mod, name) is getattr(
            projection_mod, name
        ), f"core.engine.{name} diverged from core.report_helpers_projection.{name}"


def test_observable_helpers_are_reexported_from_facade() -> None:
    for name in OBSERVABLE_NAMES:
        assert getattr(helpers_mod, name) is getattr(
            observables_mod, name
        ), f"core.report_helpers.{name} diverged from core.report_helpers_observables.{name}"
        assert hasattr(engine_mod, name), f"core.engine no longer re-exports {name}"
        assert getattr(engine_mod, name) is getattr(
            observables_mod, name
        ), f"core.engine.{name} diverged from core.report_helpers_observables.{name}"


def test_adjustment_helpers_are_reexported_from_facade() -> None:
    for name in ADJUSTMENT_NAMES:
        assert getattr(helpers_mod, name) is getattr(
            adjustment_mod, name
        ), f"core.report_helpers.{name} diverged from core.report_helpers_adjustment.{name}"
        assert hasattr(engine_mod, name), f"core.engine no longer re-exports {name}"
        assert getattr(engine_mod, name) is getattr(
            adjustment_mod, name
        ), f"core.engine.{name} diverged from core.report_helpers_adjustment.{name}"


def test_risk_helpers_are_reexported_from_facade() -> None:
    for name in RISK_NAMES:
        assert getattr(helpers_mod, name) is getattr(
            risk_mod, name
        ), f"core.report_helpers.{name} diverged from core.report_helpers_risk.{name}"
        assert hasattr(engine_mod, name), f"core.engine no longer re-exports {name}"
        assert getattr(engine_mod, name) is getattr(
            risk_mod, name
        ), f"core.engine.{name} diverged from core.report_helpers_risk.{name}"


def test_discarded_helpers_are_reexported_from_facade() -> None:
    for name in ("_summarize_discarded_mutations", "_build_discarded_mutation_priority"):
        assert getattr(helpers_mod, name) is getattr(
            discarded_mod, name
        ), f"core.report_helpers.{name} diverged from core.report_helpers_discarded.{name}"
        assert hasattr(engine_mod, name), f"core.engine no longer re-exports {name}"
        assert getattr(engine_mod, name) is getattr(
            discarded_mod, name
        ), f"core.engine.{name} diverged from core.report_helpers_discarded.{name}"


def test_evidence_sorting_helper_is_reexported_from_facade() -> None:
    assert getattr(helpers_mod, "_sort_pass_evidence") is getattr(
        evidence_sorting_mod,
        "_sort_pass_evidence",
    ), "core.report_helpers._sort_pass_evidence diverged from report_evidence_sorting._sort_pass_evidence"
    assert hasattr(engine_mod, "_sort_pass_evidence"), "core.engine no longer re-exports _sort_pass_evidence"
    assert getattr(engine_mod, "_sort_pass_evidence") is getattr(
        evidence_sorting_mod,
        "_sort_pass_evidence",
    ), "core.engine._sort_pass_evidence diverged from report_evidence_sorting._sort_pass_evidence"


def test_symbolic_helpers_are_reexported_from_facade() -> None:
    for name in (
        "_build_symbolic_summary_for_pass",
        "_summarize_symbolic_coverage_by_pass",
        "_summarize_symbolic_issue_passes",
        "_summarize_symbolic_overview",
        "_summarize_symbolic_severity_by_pass",
        "_summarize_symbolic_statuses",
    ):
        assert getattr(helpers_mod, name) is getattr(
            symbolic_summary_mod, name
        ), f"core.report_helpers.{name} diverged from core.report_helpers_symbolic_summary.{name}"
        assert hasattr(engine_mod, name), f"core.engine no longer re-exports {name}"
        assert getattr(engine_mod, name) is getattr(
            symbolic_summary_mod, name
        ), f"core.engine.{name} diverged from core.report_helpers_symbolic_summary.{name}"


def test_symbolic_view_helper_is_reexported_from_report_helpers() -> None:
    assert getattr(helpers_mod, "_summarize_symbolic_view_from_mutations") is getattr(
        symbolic_view_mod, "_summarize_symbolic_view_from_mutations"
    )


def test_report_schema_version_value() -> None:
    assert helpers_mod.REPORT_SCHEMA_VERSION == 1
    assert engine_mod.REPORT_SCHEMA_VERSION == 1
