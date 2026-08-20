"""Contract tests for pass dependency models."""

from __future__ import annotations

from r2morph.mutations.pass_dependency_models import (
    DependencyType,
    DependencyViolation,
    PassDependency,
)
from tests.utils.assertions import expect
from tests.utils.field_names import SOURCE_STAGE_KEY, TARGET_STAGE_KEY


def test_dependency_type_values() -> None:
    expect(DependencyType.REQUIRES.value == "requires")
    expect(DependencyType.CONFLICTS_WITH.value == "conflicts_with")
    expect(DependencyType.RECOMMENDS.value == "recommends")
    expect(DependencyType.REQUIRES_ABSENCE.value == "requires_absence")


def test_pass_dependency_serialization_and_string() -> None:
    dep = PassDependency(
        **{SOURCE_STAGE_KEY: "control_flow_flattening"},
        **{TARGET_STAGE_KEY: "instruction_substitution"},
        dep_type=DependencyType.REQUIRES,
        reason="dispatcher support",
    )

    expect(dep.to_dict()["dep_type"] == "requires")
    expect(not ("requires" not in str(dep)))


def test_dependency_violation_serialization() -> None:
    violation = DependencyViolation(
        **{SOURCE_STAGE_KEY: "block_reordering"},
        **{TARGET_STAGE_KEY: "nop_insertion"},
        violation_type="missing_recommendation",
        message="block reordering works better after nop insertion",
        severity="warning",
    )

    expect(violation.to_dict()["severity"] == "warning")
