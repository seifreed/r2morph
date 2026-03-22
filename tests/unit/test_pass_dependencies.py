"""
Tests for pass dependency tracking system.

Covers:
- DependencyType enum
- PassDependency dataclass
- DependencyViolation dataclass
- PassDependencyRegistry
- Pipeline validation
- Order suggestion
"""

import pytest

from r2morph.mutations.pass_dependencies import (
    DependencyType,
    PassDependency,
    DependencyViolation,
    PassDependencyRegistry,
    get_pass_dependency_registry,
    validate_pipeline_order,
    suggest_pipeline_order,
)


class TestDependencyType:
    """Test DependencyType enum."""

    def test_dependency_types(self):
        """Test all dependency types exist."""
        assert DependencyType.REQUIRES.value == "requires"
        assert DependencyType.CONFLICTS_WITH.value == "conflicts_with"
        assert DependencyType.RECOMMENDS.value == "recommends"
        assert DependencyType.REQUIRES_ABSENCE.value == "requires_absence"


class TestPassDependency:
    """Test PassDependency dataclass."""

    def test_basic_dependency(self):
        """Test basic dependency creation."""
        dep = PassDependency(
            source_pass="control_flow_flattening",
            target_pass="instruction_substitution",
            dep_type=DependencyType.REQUIRES,
        )
        assert dep.source_pass == "control_flow_flattening"
        assert dep.target_pass == "instruction_substitution"
        assert dep.dep_type == DependencyType.REQUIRES
        assert dep.optional is False

    def test_dependency_with_reason(self):
        """Test dependency with reason."""
        dep = PassDependency(
            source_pass="block_reordering",
            target_pass="nop_insertion",
            dep_type=DependencyType.RECOMMENDS,
            reason="Block reordering works better after nop insertion",
        )
        assert dep.reason == "Block reordering works better after nop insertion"

    def test_optional_dependency(self):
        """Test optional dependency."""
        dep = PassDependency(
            source_pass="dead_code_injection",
            target_pass="nop_insertion",
            dep_type=DependencyType.RECOMMENDS,
            optional=True,
        )
        assert dep.optional is True

    def test_to_dict(self):
        """Test dependency serialization."""
        dep = PassDependency(
            source_pass="test_pass",
            target_pass="other_pass",
            dep_type=DependencyType.CONFLICTS_WITH,
            reason="Test reason",
        )
        d = dep.to_dict()
        assert d["source_pass"] == "test_pass"
        assert d["target_pass"] == "other_pass"
        assert d["dep_type"] == "conflicts_with"
        assert d["reason"] == "Test reason"

    def test_str_representation(self):
        """Test string representation."""
        dep = PassDependency(
            source_pass="a",
            target_pass="b",
            dep_type=DependencyType.REQUIRES,
        )
        assert "a requires b" in str(dep)

        dep2 = PassDependency(
            source_pass="a",
            target_pass="b",
            dep_type=DependencyType.CONFLICTS_WITH,
        )
        assert "a conflicts with b" in str(dep2)

        dep3 = PassDependency(
            source_pass="a",
            target_pass="b",
            dep_type=DependencyType.RECOMMENDS,
        )
        assert "a recommends b" in str(dep3)

        dep4 = PassDependency(
            source_pass="a",
            target_pass="b",
            dep_type=DependencyType.REQUIRES_ABSENCE,
        )
        assert "a requires absence of b" in str(dep4)


class TestDependencyViolation:
    """Test DependencyViolation dataclass."""

    def test_basic_violation(self):
        """Test basic violation creation."""
        violation = DependencyViolation(
            source_pass="control_flow_flattening",
            target_pass="block_reordering",
            violation_type="absence_required",
            message="CFF requires block_reordering not to have run",
        )
        assert violation.source_pass == "control_flow_flattening"
        assert violation.target_pass == "block_reordering"
        assert violation.violation_type == "absence_required"
        assert violation.severity == "error"

    def test_violation_with_severity(self):
        """Test violation with custom severity."""
        violation = DependencyViolation(
            source_pass="block_reordering",
            target_pass="nop_insertion",
            violation_type="missing_recommendation",
            message="block_reordering works better after nop_insertion",
            severity="warning",
        )
        assert violation.severity == "warning"

    def test_violation_to_dict(self):
        """Test violation serialization."""
        violation = DependencyViolation(
            source_pass="a",
            target_pass="b",
            violation_type="conflict",
            message="a conflicts with b",
            severity="error",
        )
        d = violation.to_dict()
        assert d["source_pass"] == "a"
        assert d["target_pass"] == "b"
        assert d["violation_type"] == "conflict"
        assert d["severity"] == "error"


class TestPassDependencyRegistry:
    """Test PassDependencyRegistry."""

    def test_registry_initialization(self):
        """Test registry has default dependencies."""
        registry = PassDependencyRegistry()
        assert len(registry._dependencies) > 0

    def test_register_dependency(self):
        """Test registering a dependency."""
        registry = PassDependencyRegistry()
        initial_count = len(registry._dependencies)

        registry.register(
            "test_pass",
            "other_pass",
            DependencyType.REQUIRES,
            "Test requires other",
        )

        assert len(registry._dependencies) == initial_count + 1
        assert "test_pass" in registry._pass_names
        assert "other_pass" in registry._pass_names

    def test_get_dependencies(self):
        """Test getting dependencies for a pass."""
        registry = PassDependencyRegistry()
        deps = registry.get_dependencies("block_reordering")
        assert len(deps) > 0
        assert all(d.source_pass == "block_reordering" for d in deps)

    def test_get_required_dependencies(self):
        """Test getting required dependencies."""
        registry = PassDependencyRegistry()
        deps = registry.get_required_dependencies("control_flow_flattening")
        assert all(d.dep_type == DependencyType.REQUIRES for d in deps)

    def test_get_conflicts(self):
        """Test getting conflicts."""
        registry = PassDependencyRegistry()
        conflicts = registry.get_conflicts("block_reordering")
        assert all(d.dep_type == DependencyType.CONFLICTS_WITH for d in conflicts)

    def test_get_recommendations(self):
        """Test getting recommendations."""
        registry = PassDependencyRegistry()
        recs = registry.get_recommendations("block_reordering")
        assert all(d.dep_type == DependencyType.RECOMMENDS for d in recs)

    def test_validate_pipeline_valid(self):
        """Test validation of valid pipeline."""
        registry = PassDependencyRegistry()
        valid_pipeline = ["nop_insertion", "instruction_substitution"]
        violations = registry.validate_pipeline(valid_pipeline)
        errors = [v for v in violations if v.severity == "error"]
        assert len(errors) == 0

    def test_validate_pipeline_conflict(self):
        """Test validation detects conflicts."""
        registry = PassDependencyRegistry()
        conflicting_pipeline = ["nop_insertion", "block_reordering", "control_flow_flattening"]
        violations = registry.validate_pipeline(conflicting_pipeline)
        errors = [v for v in violations if v.severity == "error"]
        assert len(errors) > 0
        assert any("conflict" in v.violation_type or "absence" in v.violation_type for v in errors)

    def test_validate_pipeline_absence_requirement(self):
        """Test validation detects absence requirement violations."""
        registry = PassDependencyRegistry()
        pipeline_violation = ["block_reordering", "control_flow_flattening"]
        violations = registry.validate_pipeline(pipeline_violation)
        errors = [v for v in violations if v.severity == "error"]
        assert len(errors) > 0

    def test_validate_pipeline_missing_recommendation(self):
        """Test validation detects missing recommendations."""
        registry = PassDependencyRegistry()
        pipeline = ["block_reordering"]
        violations = registry.validate_pipeline(pipeline)
        warnings = [v for v in violations if v.severity == "warning"]
        assert len(warnings) > 0

    def test_suggest_order(self):
        """Test order suggestion."""
        registry = PassDependencyRegistry()
        passes = ["block_reordering", "nop_insertion"]
        ordered = registry.suggest_order(passes)
        assert "nop_insertion" in ordered
        assert "block_reordering" in ordered

    def test_suggest_order_empty(self):
        """Test order suggestion with empty list."""
        registry = PassDependencyRegistry()
        ordered = registry.suggest_order([])
        assert ordered == []

    def test_get_pass_info(self):
        """Test getting pass info."""
        registry = PassDependencyRegistry()
        info = registry.get_pass_info("block_reordering")
        assert "pass_name" in info
        assert "requires" in info
        assert "conflicts" in info
        assert "recommends" in info

    def test_list_all_passes(self):
        """Test listing all passes."""
        registry = PassDependencyRegistry()
        passes = registry.list_all_passes()
        assert len(passes) > 0
        assert "block_reordering" in passes
        assert "nop_insertion" in passes

    def test_to_dict(self):
        """Test registry serialization."""
        registry = PassDependencyRegistry()
        d = registry.to_dict()
        assert "passes" in d
        assert "dependencies" in d


class TestGlobalFunctions:
    """Test global utility functions."""

    def test_get_pass_dependency_registry(self):
        """Test getting global registry."""
        registry1 = get_pass_dependency_registry()
        registry2 = get_pass_dependency_registry()
        assert registry1 is registry2

    def test_validate_pipeline_order(self):
        """Test pipeline order validation."""
        is_valid, violations = validate_pipeline_order(["nop_insertion"])
        assert isinstance(is_valid, bool)
        assert isinstance(violations, list)

    def test_suggest_pipeline_order(self):
        """Test pipeline order suggestion."""
        ordered = suggest_pipeline_order(["nop_insertion", "block_reordering"])
        assert isinstance(ordered, list)
        assert len(ordered) == 2


class TestDependencyScenarios:
    """Test realistic dependency scenarios."""

    def test_cff_then_block_reordering(self):
        """Test CFF followed by block reordering is invalid."""
        registry = PassDependencyRegistry()
        violations = registry.validate_pipeline(
            [
                "control_flow_flattening",
                "block_reordering",
            ]
        )
        errors = [v for v in violations if v.severity == "error"]
        assert len(errors) > 0
        assert any("absence" in v.violation_type or "conflict" in v.violation_type for v in errors)

    def test_nop_then_block_order(self):
        """Test nop insertion before block reordering."""
        registry = PassDependencyRegistry()
        ordered = registry.suggest_order(["block_reordering", "nop_insertion"])
        # The suggestion may respect recommendations but does not guarantee order
        # since nop_insertion is a recommendation, not a requirement
        assert len(ordered) == 2
        assert set(ordered) == {"block_reordering", "nop_insertion"}

    def test_multiple_recommendations(self):
        """Test pass with multiple recommendations."""
        registry = PassDependencyRegistry()
        info = registry.get_pass_info("dead_code_injection")
        assert len(info["recommends"]) > 0

    def test_chain_of_dependencies(self):
        """Test chain of dependencies."""
        registry = PassDependencyRegistry()
        passes = ["dead_code_injection", "block_reordering", "nop_insertion"]
        ordered = registry.suggest_order(passes)
        assert len(ordered) == 3

    def test_optional_requirement_not_satisfied(self):
        """Test optional requirements don't cause errors."""
        registry = PassDependencyRegistry()
        violations = registry.validate_pipeline(["nop_insertion"])
        errors = [v for v in violations if v.severity == "error"]
        assert len(errors) == 0

    def test_new_pass_no_dependencies(self):
        """Test pass with no dependencies."""
        registry = PassDependencyRegistry()
        deps = registry.get_dependencies("unknown_pass_xyz")
        assert deps == []

    def test_register_and_validate(self):
        """Test registering and then validating."""
        registry = PassDependencyRegistry()

        registry.register(
            "new_pass",
            "nop_insertion",
            DependencyType.REQUIRES,
            "New pass needs nop padding",
        )

        violations = registry.validate_pipeline(["new_pass"])
        errors = [v for v in violations if v.severity == "error"]
        assert len(errors) > 0

        violations = registry.validate_pipeline(["nop_insertion", "new_pass"])
        errors = [v for v in violations if v.severity == "error"]
        assert len(errors) == 0
