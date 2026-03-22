"""
Tests for semantic validation module.

Covers:
- Invariant checking (stack balance, register preservation)
- Semantic validation reports
- CI integration
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from r2morph.validation.semantic_invariants import (
    InvariantCategory,
    InvariantSeverity,
    InvariantSpec,
    InvariantViolation,
    SemanticInvariantRegistry,
    StackBalanceChecker,
    RegisterPreservationChecker,
    ControlFlowPreservationChecker,
    SemanticInvariantChecker,
)
from r2morph.validation.semantic import (
    ValidationMode,
    ValidationResultStatus,
    MutationRegion,
    SemanticCheck,
    ObservableComparison,
    SemanticValidationResult,
    SemanticValidationReport,
    SemanticValidator,
    validate_semantic_equivalence,
)


class TestInvariantSpec:
    """Test InvariantSpec dataclass."""

    def test_invariant_creation(self):
        """Create an invariant spec."""
        inv = InvariantSpec(
            name="stack_balance",
            category=InvariantCategory.STACK,
            description="Stack must be balanced",
        )
        assert inv.name == "stack_balance"
        assert inv.category == InvariantCategory.STACK
        assert inv.check_required is True

    def test_invariant_with_pass_types(self):
        """Create invariant with pass types."""
        inv = InvariantSpec(
            name="callee_saved",
            category=InvariantCategory.REGISTER,
            description="Callee-saved registers preserved",
            pass_types=["nop", "substitute"],
        )
        assert "nop" in inv.pass_types
        assert "substitute" in inv.pass_types


class TestInvariantViolation:
    """Test InvariantViolation dataclass."""

    def test_violation_creation(self):
        """Create a violation."""
        violation = InvariantViolation(
            invariant_name="stack_balance",
            category=InvariantCategory.STACK,
            severity=InvariantSeverity.ERROR,
            address_range=(0x1000, 0x1010),
            message="Stack delta mismatch",
        )
        assert violation.invariant_name == "stack_balance"
        assert violation.severity == InvariantSeverity.ERROR

    def test_violation_to_dict(self):
        """Convert violation to dictionary."""
        violation = InvariantViolation(
            invariant_name="stack_balance",
            category=InvariantCategory.STACK,
            severity=InvariantSeverity.ERROR,
            address_range=(0x1000, 0x1010),
            message="Stack delta mismatch",
            expected=0,
            actual=8,
        )
        d = violation.to_dict()
        assert d["invariant_name"] == "stack_balance"
        assert d["severity"] == "error"
        assert d["address_range"] == [0x1000, 0x1010]


class TestSemanticInvariantRegistry:
    """Test SemanticInvariantRegistry."""

    def test_registry_has_standard_invariants(self):
        """Registry has standard invariants."""
        registry = SemanticInvariantRegistry()
        assert "stack_balance" in registry._invariants
        assert "callee_saved_preservation" in registry._invariants

    def test_get_invariants_for_pass(self):
        """Get invariants for a pass type."""
        registry = SemanticInvariantRegistry()
        invariants = registry.get_invariants_for_pass("nop")
        assert len(invariants) > 0
        assert any(inv.name == "stack_balance" for inv in invariants)

    def test_get_required_invariants(self):
        """Get only required invariants."""
        registry = SemanticInvariantRegistry()
        invariants = registry.get_required_invariants("substitute")
        for inv in invariants:
            assert inv.check_required is True

    def test_register_new_invariant(self):
        """Register a new invariant."""
        registry = SemanticInvariantRegistry()
        new_inv = InvariantSpec(
            name="custom_invariant",
            category=InvariantCategory.SIDE_EFFECT,
            description="Custom check",
            pass_types=["custom"],
        )
        registry.register_invariant(new_inv)
        assert "custom_invariant" in registry._invariants


class TestStackBalanceChecker:
    """Test StackBalanceChecker."""

    def test_check_region_no_change(self):
        """Check region with no stack change."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        checker = StackBalanceChecker(mock_binary)
        original = b"\x90\x90\x90"
        mutated = b"\x90\x90\x90"

        violations = checker.check_region(0x1000, 0x1003, original, mutated)
        assert len(violations) == 0

    def test_check_region_push_pop_balance(self):
        """Check region with balanced push/pop."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        checker = StackBalanceChecker(mock_binary)
        original = b"\x50\x58"
        mutated = b"\x51\x59"

        violations = checker.check_region(0x1000, 0x1002, original, mutated)
        assert len(violations) == 0

    def test_check_region_stack_mismatch(self):
        """Check region with stack imbalance."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        checker = StackBalanceChecker(mock_binary)
        original = b"\x50\x50\x58"
        mutated = b"\x50\x58"

        violations = checker.check_region(0x1000, 0x1003, original, mutated)
        assert len(violations) == 1
        assert violations[0].invariant_name == "stack_balance"


class TestRegisterPreservationChecker:
    """Test RegisterPreservationChecker."""

    def test_get_callee_saved_x86_64(self):
        """Get callee-saved registers for x86_64."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        checker = RegisterPreservationChecker(mock_binary)
        regs = checker.get_callee_saved_registers()

        assert "rbx" in regs
        assert "r12" in regs
        assert "rbp" in regs

    def test_get_callee_saved_x86(self):
        """Get callee-saved registers for x86."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86", "bits": 32}

        checker = RegisterPreservationChecker(mock_binary)
        regs = checker.get_callee_saved_registers()

        assert "ebx" in regs
        assert "esi" in regs
        assert "edi" in regs

    def test_check_callee_saved_violation(self):
        """Check detects callee-saved register modification."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        checker = RegisterPreservationChecker(mock_binary)
        violations = checker.check_register_usage(0x1000, 0x1010, "nop", {"rbx", "rax"})

        assert len(violations) == 1
        assert violations[0].invariant_name == "callee_saved_preservation"


class TestControlFlowPreservationChecker:
    """Test ControlFlowPreservationChecker."""

    def test_successor_preservation_pass(self):
        """Check preserves successors."""
        mock_binary = MagicMock()
        checker = ControlFlowPreservationChecker(mock_binary)

        violations = checker.check_successor_preservation(
            0x1000,
            0x1010,
            [0x1100, 0x1200],
            [0x1100, 0x1200],
        )
        assert len(violations) == 0

    def test_missing_successor(self):
        """Check detects missing successor."""
        mock_binary = MagicMock()
        checker = ControlFlowPreservationChecker(mock_binary)

        violations = checker.check_successor_preservation(
            0x1000,
            0x1010,
            [0x1100, 0x1200],
            [0x1100],
        )
        assert len(violations) == 1
        assert violations[0].invariant_name == "control_flow_preservation"

    def test_extra_successor(self):
        """Check detects extra successor."""
        mock_binary = MagicMock()
        checker = ControlFlowPreservationChecker(mock_binary)

        violations = checker.check_successor_preservation(
            0x1000,
            0x1010,
            [0x1100],
            [0x1100, 0x1200],
        )
        assert len(violations) == 1


class TestSemanticInvariantChecker:
    """Test SemanticInvariantChecker."""

    def test_check_mutation_pass(self):
        """Check mutation passes all invariants."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        checker = SemanticInvariantChecker(mock_binary)
        violations = checker.check_mutation(
            pass_type="nop",
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\x90" * 16,
        )
        assert len(violations) == 0

    def test_invariant_summary(self):
        """Get invariant summary."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        checker = SemanticInvariantChecker(mock_binary)
        violations = [
            InvariantViolation(
                invariant_name="stack_balance",
                category=InvariantCategory.STACK,
                severity=InvariantSeverity.ERROR,
                address_range=(0x1000, 0x1010),
                message="Stack imbalance",
            ),
        ]
        summary = checker.get_invariant_summary(violations)

        assert summary["total_violations"] == 1
        assert summary["by_severity"]["error"] == 1
        assert summary["passed"] is False


class TestMutationRegion:
    """Test MutationRegion dataclass."""

    def test_region_creation(self):
        """Create a mutation region."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\xcc" * 16,
            pass_name="nop",
        )
        assert region.start_address == 0x1000
        assert region.pass_name == "nop"

    def test_region_to_dict(self):
        """Convert region to dictionary."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\xcc" * 16,
            pass_name="nop",
            function_address=0x1000,
        )
        d = region.to_dict()
        assert d["start_address"] == 0x1000
        assert d["original_bytes"] == "90" * 16
        assert d["mutated_bytes"] == "cc" * 16


class TestSemanticValidationReport:
    """Test SemanticValidationReport."""

    def test_report_creation(self):
        """Create a validation report."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\x90" * 16,
            pass_name="nop",
        )
        result = SemanticValidationResult(
            region=region,
            status=ValidationResultStatus.PASS,
        )
        report = SemanticValidationReport(
            binary_path="/tmp/test",
            timestamp="2024-01-01T00:00:00",
            mode=ValidationMode.STANDARD,
            results=[result],
        )

        assert report.summary["total_mutations"] == 1
        assert report.summary["passed"] == 1
        assert report.summary["overall_status"] == "pass"

    def test_report_to_json(self):
        """Convert report to JSON."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\x90" * 16,
            pass_name="nop",
        )
        result = SemanticValidationResult(
            region=region,
            status=ValidationResultStatus.PASS,
        )
        report = SemanticValidationReport(
            binary_path="/tmp/test",
            timestamp="2024-01-01T00:00:00",
            mode=ValidationMode.STANDARD,
            results=[result],
        )

        json_str = report.to_json()
        assert '"total_mutations"' in json_str
        assert '"status": "pass"' in json_str

    def test_report_write_load(self, tmp_path):
        """Write and load report."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\x90" * 16,
            pass_name="nop",
        )
        result = SemanticValidationResult(
            region=region,
            status=ValidationResultStatus.PASS,
        )
        report = SemanticValidationReport(
            binary_path="/tmp/test",
            timestamp="2024-01-01T00:00:00",
            mode=ValidationMode.STANDARD,
            results=[result],
        )

        report_path = tmp_path / "report.json"
        report.write_report(report_path)

        loaded = SemanticValidationReport.load_report(report_path)
        assert loaded.binary_path == "/tmp/test"
        assert loaded.mode == ValidationMode.STANDARD


class TestSemanticValidator:
    """Test SemanticValidator."""

    def test_validator_creation(self):
        """Create a semantic validator."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        validator = SemanticValidator(mock_binary, ValidationMode.FAST)
        assert validator.mode == ValidationMode.FAST
        assert validator.invariant_checker is not None

    def test_validate_mutation_pass(self):
        """Validate a passing mutation."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}
        mock_binary.path = "/tmp/test"

        validator = SemanticValidator(mock_binary)
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\x90" * 16,
            pass_name="nop",
        )

        result = validator.validate_mutation(region)
        assert result.status == ValidationResultStatus.PASS

    def test_validate_mutations(self):
        """Validate multiple mutations."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}
        mock_binary.path = "/tmp/test"

        validator = SemanticValidator(mock_binary)
        regions = [
            MutationRegion(
                start_address=0x1000,
                end_address=0x1010,
                original_bytes=b"\x90" * 16,
                mutated_bytes=b"\x90" * 16,
                pass_name="nop",
            ),
            MutationRegion(
                start_address=0x2000,
                end_address=0x2010,
                original_bytes=b"\x90" * 16,
                mutated_bytes=b"\x90" * 16,
                pass_name="nop",
            ),
        ]

        report = validator.validate_mutations(regions)
        assert report.summary["total_mutations"] == 2
        assert report.summary["passed"] == 2


class TestValidateSemanticEquivalence:
    """Test convenience function."""

    def test_convenience_function(self):
        """Test validate_semantic_equivalence function."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}
        mock_binary.path = "/tmp/test"

        mutations = [
            {
                "start_address": 0x1000,
                "end_address": 0x1010,
                "original_bytes": "90" * 16,
                "mutated_bytes": "90" * 16,
                "pass_name": "nop",
            }
        ]

        report = validate_semantic_equivalence(
            binary=mock_binary,
            mutations=mutations,
            mode="standard",
        )

        assert "summary" in report
        assert report["summary"]["total_mutations"] == 1


class TestValidationModes:
    """Test validation modes."""

    def test_fast_mode(self):
        """Fast mode should skip symbolic."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        validator = SemanticValidator(mock_binary, ValidationMode.FAST)
        assert validator.mode == ValidationMode.FAST

    def test_standard_mode(self):
        """Standard mode."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        validator = SemanticValidator(mock_binary, ValidationMode.STANDARD)
        assert validator.mode == ValidationMode.STANDARD

    def test_thorough_mode(self):
        """Thorough mode."""
        mock_binary = MagicMock()
        mock_binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        validator = SemanticValidator(mock_binary, ValidationMode.THOROUGH)
        assert validator.mode == ValidationMode.THOROUGH


class TestObservableComparison:
    """Test ObservableComparison."""

    def test_observable_creation(self):
        """Create observable comparison."""
        obs = ObservableComparison(
            register_matches={"rax": True, "rbx": True},
            flag_matches={"cf": True, "zf": True},
            stack_delta_match=True,
            successor_match=True,
        )
        assert obs.register_matches["rax"] is True
        assert obs.stack_delta_match is True

    def test_observable_to_dict(self):
        """Convert observable to dictionary."""
        obs = ObservableComparison(
            register_matches={"rax": False},
            register_values={"rax": (0x1234, 0x5678)},
            stack_delta_match=False,
            successor_match=True,
        )
        d = obs.to_dict()
        assert "register_matches" in d
        assert "register_values" in d
        assert d["stack_delta_match"] is False
