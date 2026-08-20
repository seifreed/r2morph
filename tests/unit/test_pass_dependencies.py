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

from r2morph.mutations.pass_dependencies import (
    DependencyType,
    DependencyViolation,
    PassDependency,
    PassDependencyRegistry,
    get_pass_dependency_registry,
    suggest_pipeline_order,
    validate_pipeline_order,
)
from tests.utils.assertions import expect
from tests.utils.field_names import SOURCE_STAGE_KEY, TARGET_STAGE_KEY

_EXPECTED_LEN_ORDERED_2 = 2
_EXPECTED_LEN_ORDERED_2_2 = 2
_EXPECTED_LEN_ORDERED_3 = 3


class TestDependencyType:
    """Test DependencyType enum."""

    def test_dependency_types(self):
        """Test all dependency types exist."""
        expect(DependencyType.REQUIRES.value == "requires")
        expect(DependencyType.CONFLICTS_WITH.value == "conflicts_with")
        expect(DependencyType.RECOMMENDS.value == "recommends")
        expect(DependencyType.REQUIRES_ABSENCE.value == "requires_absence")


class TestPassDependency:
    """Test PassDependency dataclass."""

    def test_basic_dependency(self):
        """Test basic dependency creation."""
        dep = PassDependency(
            **{SOURCE_STAGE_KEY: "control_flow_flattening"},
            **{TARGET_STAGE_KEY: "instruction_substitution"},
            dep_type=DependencyType.REQUIRES,
        )
        expect(getattr(dep, SOURCE_STAGE_KEY) == "control_flow_flattening")
        expect(getattr(dep, TARGET_STAGE_KEY) == "instruction_substitution")
        expect(dep.dep_type == DependencyType.REQUIRES)
        expect(not (dep.optional is not False))

    def test_dependency_with_reason(self):
        """Test dependency with reason."""
        dep = PassDependency(
            **{SOURCE_STAGE_KEY: "block_reordering"},
            **{TARGET_STAGE_KEY: "nop_insertion"},
            dep_type=DependencyType.RECOMMENDS,
            reason="Block reordering works better after nop insertion",
        )
        expect(dep.reason == "Block reordering works better after nop insertion")

    def test_optional_dependency(self):
        """Test optional dependency."""
        dep = PassDependency(
            **{SOURCE_STAGE_KEY: "dead_code_injection"},
            **{TARGET_STAGE_KEY: "nop_insertion"},
            dep_type=DependencyType.RECOMMENDS,
            optional=True,
        )
        expect(not (dep.optional is not True))

    def test_to_dict(self):
        """Test dependency serialization."""
        dep = PassDependency(
            **{SOURCE_STAGE_KEY: "test_pass"},
            **{TARGET_STAGE_KEY: "other_pass"},
            dep_type=DependencyType.CONFLICTS_WITH,
            reason="Test reason",
        )
        d = dep.to_dict()
        expect(d[SOURCE_STAGE_KEY] == "test_pass")
        expect(d[TARGET_STAGE_KEY] == "other_pass")
        expect(d["dep_type"] == "conflicts_with")
        expect(d["reason"] == "Test reason")

    def test_str_representation(self):
        """Test string representation."""
        dep = PassDependency(
            **{SOURCE_STAGE_KEY: "a"},
            **{TARGET_STAGE_KEY: "b"},
            dep_type=DependencyType.REQUIRES,
        )
        expect(not ("a requires b" not in str(dep)))

        dep2 = PassDependency(
            **{SOURCE_STAGE_KEY: "a"},
            **{TARGET_STAGE_KEY: "b"},
            dep_type=DependencyType.CONFLICTS_WITH,
        )
        expect(not ("a conflicts with b" not in str(dep2)))

        dep3 = PassDependency(
            **{SOURCE_STAGE_KEY: "a"},
            **{TARGET_STAGE_KEY: "b"},
            dep_type=DependencyType.RECOMMENDS,
        )
        expect(not ("a recommends b" not in str(dep3)))

        dep4 = PassDependency(
            **{SOURCE_STAGE_KEY: "a"},
            **{TARGET_STAGE_KEY: "b"},
            dep_type=DependencyType.REQUIRES_ABSENCE,
        )
        expect(not ("a requires absence of b" not in str(dep4)))


class TestDependencyViolation:
    """Test DependencyViolation dataclass."""

    def test_basic_violation(self):
        """Test basic violation creation."""
        violation = DependencyViolation(
            **{SOURCE_STAGE_KEY: "control_flow_flattening"},
            **{TARGET_STAGE_KEY: "block_reordering"},
            violation_type="absence_required",
            message="CFF requires block_reordering not to have run",
        )
        expect(getattr(violation, SOURCE_STAGE_KEY) == "control_flow_flattening")
        expect(getattr(violation, TARGET_STAGE_KEY) == "block_reordering")
        expect(violation.violation_type == "absence_required")
        expect(violation.severity == "error")

    def test_violation_with_severity(self):
        """Test violation with custom severity."""
        violation = DependencyViolation(
            **{SOURCE_STAGE_KEY: "block_reordering"},
            **{TARGET_STAGE_KEY: "nop_insertion"},
            violation_type="missing_recommendation",
            message="block_reordering works better after nop_insertion",
            severity="warning",
        )
        expect(violation.severity == "warning")

    def test_violation_to_dict(self):
        """Test violation serialization."""
        violation = DependencyViolation(
            **{SOURCE_STAGE_KEY: "a"},
            **{TARGET_STAGE_KEY: "b"},
            violation_type="conflict",
            message="a conflicts with b",
            severity="error",
        )
        d = violation.to_dict()
        expect(d[SOURCE_STAGE_KEY] == "a")
        expect(d[TARGET_STAGE_KEY] == "b")
        expect(d["violation_type"] == "conflict")
        expect(d["severity"] == "error")


class TestPassDependencyRegistry:
    """Test PassDependencyRegistry."""

    def test_registry_initialization(self):
        """Test registry has default dependencies."""
        registry = PassDependencyRegistry()
        expect(not (len(registry._dependencies) <= 0))

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

        expect(len(registry._dependencies) == initial_count + 1)
        expect(not ("test_pass" not in registry._pass_names))
        expect(not ("other_pass" not in registry._pass_names))

    def test_get_dependencies(self):
        """Test getting dependencies for a pass."""
        registry = PassDependencyRegistry()
        deps = registry.get_dependencies("block_reordering")
        expect(not (len(deps) <= 0))
        expect(all(getattr(d, SOURCE_STAGE_KEY) == "block_reordering" for d in deps))

    def test_get_required_dependencies(self):
        """Test getting required dependencies."""
        registry = PassDependencyRegistry()
        deps = registry.get_required_dependencies("control_flow_flattening")
        expect(all(d.dep_type == DependencyType.REQUIRES for d in deps))

    def test_get_conflicts(self):
        """Test getting conflicts."""
        registry = PassDependencyRegistry()
        conflicts = registry.get_conflicts("block_reordering")
        expect(all(d.dep_type == DependencyType.CONFLICTS_WITH for d in conflicts))

    def test_get_recommendations(self):
        """Test getting recommendations."""
        registry = PassDependencyRegistry()
        recs = registry.get_recommendations("block_reordering")
        expect(all(d.dep_type == DependencyType.RECOMMENDS for d in recs))

    def test_validate_pipeline_valid(self):
        """Test validation of valid pipeline."""
        registry = PassDependencyRegistry()
        valid_pipeline = ["nop_insertion", "instruction_substitution"]
        violations = registry.validate_pipeline(valid_pipeline)
        errors = [v for v in violations if v.severity == "error"]
        expect(len(errors) == 0)

    def test_validate_pipeline_conflict(self):
        """Test validation detects conflicts."""
        registry = PassDependencyRegistry()
        conflicting_pipeline = ["nop_insertion", "block_reordering", "control_flow_flattening"]
        violations = registry.validate_pipeline(conflicting_pipeline)
        errors = [v for v in violations if v.severity == "error"]
        expect(not (len(errors) <= 0))
        expect(any("conflict" in v.violation_type or "absence" in v.violation_type for v in errors))

    def test_validate_pipeline_absence_requirement(self):
        """Test validation detects absence requirement violations."""
        registry = PassDependencyRegistry()
        pipeline_violation = ["block_reordering", "control_flow_flattening"]
        violations = registry.validate_pipeline(pipeline_violation)
        errors = [v for v in violations if v.severity == "error"]
        expect(not (len(errors) <= 0))

    def test_validate_pipeline_missing_recommendation(self):
        """Test validation detects missing recommendations."""
        registry = PassDependencyRegistry()
        pipeline = ["block_reordering"]
        violations = registry.validate_pipeline(pipeline)
        warnings = [v for v in violations if v.severity == "warning"]
        expect(not (len(warnings) <= 0))

    def test_suggest_order(self):
        """Test order suggestion."""
        registry = PassDependencyRegistry()
        passes = ["block_reordering", "nop_insertion"]
        ordered = registry.suggest_order(passes)
        expect(not ("nop_insertion" not in ordered))
        expect(not ("block_reordering" not in ordered))

    def test_suggest_order_empty(self):
        """Test order suggestion with empty list."""
        registry = PassDependencyRegistry()
        ordered = registry.suggest_order([])
        expect(ordered == [])

    def test_get_pass_info(self):
        """Test getting pass info."""
        registry = PassDependencyRegistry()
        info = registry.get_pass_info("block_reordering")
        expect(not ("pass_name" not in info))
        expect(not ("requires" not in info))
        expect(not ("conflicts" not in info))
        expect(not ("recommends" not in info))

    def test_list_all_passes(self):
        """Test listing all passes."""
        registry = PassDependencyRegistry()
        passes = registry.list_all_passes()
        expect(not (len(passes) <= 0))
        expect(not ("block_reordering" not in passes))
        expect(not ("nop_insertion" not in passes))

    def test_to_dict(self):
        """Test registry serialization."""
        registry = PassDependencyRegistry()
        d = registry.to_dict()
        expect(not ("passes" not in d))
        expect(not ("dependencies" not in d))


class TestGlobalFunctions:
    """Test global utility functions."""

    def test_get_pass_dependency_registry(self):
        """Test getting global registry."""
        registry1 = get_pass_dependency_registry()
        registry2 = get_pass_dependency_registry()
        expect(not (registry1 is not registry2))

    def test_validate_pipeline_order(self):
        """Test pipeline order validation."""
        is_valid, violations = validate_pipeline_order(["nop_insertion"])
        expect(isinstance(is_valid, bool))
        expect(isinstance(violations, list))

    def test_suggest_pipeline_order(self):
        """Test pipeline order suggestion."""
        ordered = suggest_pipeline_order(["nop_insertion", "block_reordering"])
        expect(isinstance(ordered, list))
        expect(len(ordered) == _EXPECTED_LEN_ORDERED_2)


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
        expect(not (len(errors) <= 0))
        expect(any("absence" in v.violation_type or "conflict" in v.violation_type for v in errors))

    def test_nop_then_block_order(self):
        """Test nop insertion before block reordering."""
        registry = PassDependencyRegistry()
        ordered = registry.suggest_order(["block_reordering", "nop_insertion"])
        # The suggestion may respect recommendations but does not guarantee order
        # since nop_insertion is a recommendation, not a requirement
        expect(len(ordered) == _EXPECTED_LEN_ORDERED_2_2)
        expect(set(ordered) == {"block_reordering", "nop_insertion"})

    def test_multiple_recommendations(self):
        """Test pass with multiple recommendations."""
        registry = PassDependencyRegistry()
        info = registry.get_pass_info("dead_code_injection")
        expect(not (len(info["recommends"]) <= 0))

    def test_chain_of_dependencies(self):
        """Test chain of dependencies."""
        registry = PassDependencyRegistry()
        passes = ["dead_code_injection", "block_reordering", "nop_insertion"]
        ordered = registry.suggest_order(passes)
        expect(len(ordered) == _EXPECTED_LEN_ORDERED_3)

    def test_optional_requirement_not_satisfied(self):
        """Test optional requirements don't cause errors."""
        registry = PassDependencyRegistry()
        violations = registry.validate_pipeline(["nop_insertion"])
        errors = [v for v in violations if v.severity == "error"]
        expect(len(errors) == 0)

    def test_new_pass_no_dependencies(self):
        """Test pass with no dependencies."""
        registry = PassDependencyRegistry()
        deps = registry.get_dependencies("unknown_pass_xyz")
        expect(deps == [])

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
        expect(not (len(errors) <= 0))

        violations = registry.validate_pipeline(["nop_insertion", "new_pass"])
        errors = [v for v in violations if v.severity == "error"]
        expect(len(errors) == 0)
