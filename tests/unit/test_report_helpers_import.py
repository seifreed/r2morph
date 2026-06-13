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
from r2morph.core import report_helpers_projection as projection_mod
from r2morph.core import report_helpers_triage as triage_mod

REEXPORTED_NAMES = [
    "REPORT_SCHEMA_VERSION",
    "_build_discarded_mutation_priority",
    "_build_evidence_summary_for_pass",
    "_build_observable_mismatch_map",
    "_build_observable_mismatch_priority",
    "_build_pass_triage_map",
    "_build_pass_validation_context",
    "_build_symbolic_summary_for_pass",
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
    "_summarize_symbolic_coverage_by_pass",
    "_summarize_symbolic_issue_passes",
    "_summarize_symbolic_overview",
    "_summarize_symbolic_severity_by_pass",
    "_summarize_symbolic_statuses",
    "_summarize_validation_role_rows",
]

PROJECTION_NAMES = [
    "_build_pass_capability_summary_map",
    "_build_pass_region_evidence_map",
    "_summarize_normalized_pass_results",
    "_summarize_pass_capability_rows",
]

ADJUSTMENT_NAMES = [
    "_summarize_validation_adjustment_rows",
    "_summarize_validation_adjustments",
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


def test_canonical_adjustment_module_defines_adjustment_helpers() -> None:
    for name in ADJUSTMENT_NAMES:
        assert hasattr(adjustment_mod, name), f"core.report_helpers_adjustment missing {name}"


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


def test_adjustment_helpers_are_reexported_from_facade() -> None:
    for name in ADJUSTMENT_NAMES:
        assert getattr(helpers_mod, name) is getattr(
            adjustment_mod, name
        ), f"core.report_helpers.{name} diverged from core.report_helpers_adjustment.{name}"
        assert hasattr(engine_mod, name), f"core.engine no longer re-exports {name}"
        assert getattr(engine_mod, name) is getattr(
            adjustment_mod, name
        ), f"core.engine.{name} diverged from core.report_helpers_adjustment.{name}"


def test_report_schema_version_value() -> None:
    assert helpers_mod.REPORT_SCHEMA_VERSION == 1
    assert engine_mod.REPORT_SCHEMA_VERSION == 1
