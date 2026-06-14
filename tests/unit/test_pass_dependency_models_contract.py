"""Contract tests for pass dependency models."""

from __future__ import annotations

from r2morph.mutations.pass_dependency_models import (
    DependencyType,
    DependencyViolation,
    PassDependency,
)


def test_dependency_type_values() -> None:
    assert DependencyType.REQUIRES.value == "requires"
    assert DependencyType.CONFLICTS_WITH.value == "conflicts_with"
    assert DependencyType.RECOMMENDS.value == "recommends"
    assert DependencyType.REQUIRES_ABSENCE.value == "requires_absence"


def test_pass_dependency_serialization_and_string() -> None:
    dep = PassDependency(
        source_pass="control_flow_flattening",
        target_pass="instruction_substitution",
        dep_type=DependencyType.REQUIRES,
        reason="dispatcher support",
    )

    assert dep.to_dict()["dep_type"] == "requires"
    assert "requires" in str(dep)


def test_dependency_violation_serialization() -> None:
    violation = DependencyViolation(
        source_pass="block_reordering",
        target_pass="nop_insertion",
        violation_type="missing_recommendation",
        message="block reordering works better after nop insertion",
        severity="warning",
    )

    assert violation.to_dict()["severity"] == "warning"
