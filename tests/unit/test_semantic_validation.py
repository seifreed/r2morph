"""
Tests for semantic validation module.

Covers:
- Invariant checking (stack balance, register preservation)
- Semantic validation reports
- CI integration
"""

from r2morph.validation.semantic import (
    MutationRegion,
    ObservableComparison,
    SemanticValidationReport,
    SemanticValidationResult,
    SemanticValidator,
    ValidationMode,
    ValidationResultStatus,
    validate_semantic_equivalence,
)
from r2morph.validation.semantic_invariants import (
    ControlFlowPreservationChecker,
    InvariantCategory,
    InvariantSeverity,
    InvariantSpec,
    InvariantViolation,
    RegisterPreservationChecker,
    SemanticInvariantChecker,
    SemanticInvariantRegistry,
    StackBalanceChecker,
)
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY

_EXPECTED_D_START_ADDRESS_4096 = 0x1000
_EXPECTED_REGION_START_ADDRESS_4096 = 0x1000
_EXPECTED_REPORT_SUMMARY_PASSED_2 = 2
_EXPECTED_REPORT_SUMMARY_TOTAL_MUTATIONS_2 = 2


class _Binary:
    def __init__(self, arch: str = "x86_64", bits: int = 64) -> None:
        self.path = "test-data/test"
        self.arch_info = {"arch": arch, "bits": bits}

    def get_arch_info(self) -> dict[str, str | int]:
        return self.arch_info


class TestInvariantSpec:
    """Test InvariantSpec dataclass."""

    def test_invariant_creation(self):
        """Create an invariant spec."""
        inv = InvariantSpec(
            name="stack_balance",
            category=InvariantCategory.STACK,
            description="Stack must be balanced",
        )
        expect(inv.name == "stack_balance")
        expect(inv.category == InvariantCategory.STACK)
        expect(not (inv.check_required is not True))

    def test_invariant_with_pass_types(self):
        """Create invariant with pass types."""
        inv = InvariantSpec(
            name="callee_saved",
            category=InvariantCategory.REGISTER,
            description="Callee-saved registers preserved",
            pass_types=["nop", "substitute"],
        )
        expect(not ("nop" not in inv.pass_types))
        expect(not ("substitute" not in inv.pass_types))


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
        expect(violation.invariant_name == "stack_balance")
        expect(violation.severity == InvariantSeverity.ERROR)

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
        expect(d["invariant_name"] == "stack_balance")
        expect(d["severity"] == "error")
        expect(d["address_range"] == [4096, 4112])


class TestSemanticInvariantRegistry:
    """Test SemanticInvariantRegistry."""

    def test_registry_has_standard_invariants(self):
        """Registry has standard invariants."""
        registry = SemanticInvariantRegistry()
        expect(not ("stack_balance" not in registry._invariants))
        expect(not ("callee_saved_preservation" not in registry._invariants))

    def test_get_invariants_for_pass(self):
        """Get invariants for a pass type."""
        registry = SemanticInvariantRegistry()
        invariants = registry.get_invariants_for_pass("nop")
        expect(not (len(invariants) <= 0))
        expect(any(inv.name == "stack_balance" for inv in invariants))

    def test_get_required_invariants(self):
        """Get only required invariants."""
        registry = SemanticInvariantRegistry()
        invariants = registry.get_required_invariants("substitute")
        for inv in invariants:
            expect(not (inv.check_required is not True))

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
        expect(not ("custom_invariant" not in registry._invariants))


class TestStackBalanceChecker:
    """Test StackBalanceChecker."""

    def test_check_region_no_change(self):
        """Check region with no stack change."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        checker = StackBalanceChecker(mock_binary)
        original = b"\x90\x90\x90"
        mutated = b"\x90\x90\x90"

        violations = checker.check_region(0x1000, 0x1003, original, mutated)
        expect(len(violations) == 0)

    def test_check_region_push_pop_balance(self):
        """Check region with balanced push/pop."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        checker = StackBalanceChecker(mock_binary)
        original = b"\x50\x58"
        mutated = b"\x51\x59"

        violations = checker.check_region(0x1000, 0x1002, original, mutated)
        expect(len(violations) == 0)

    def test_check_region_stack_mismatch(self):
        """Check region with stack imbalance."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        checker = StackBalanceChecker(mock_binary)
        original = b"\x50\x50\x58"
        mutated = b"\x50\x58"

        violations = checker.check_region(0x1000, 0x1003, original, mutated)
        expect(len(violations) == 1)
        expect(violations[0].invariant_name == "stack_balance")


class TestRegisterPreservationChecker:
    """Test RegisterPreservationChecker."""

    def test_get_callee_saved_x86_64(self):
        """Get callee-saved registers for x86_64."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        checker = RegisterPreservationChecker(mock_binary)
        regs = checker.get_callee_saved_registers()

        expect(not ("rbx" not in regs))
        expect(not ("r12" not in regs))
        expect(not ("rbp" not in regs))

    def test_get_callee_saved_x86(self):
        """Get callee-saved registers for x86."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86", "bits": 32}

        checker = RegisterPreservationChecker(mock_binary)
        regs = checker.get_callee_saved_registers()

        expect(not ("ebx" not in regs))
        expect(not ("esi" not in regs))
        expect(not ("edi" not in regs))

    def test_check_callee_saved_violation(self):
        """Check detects callee-saved register modification."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        checker = RegisterPreservationChecker(mock_binary)
        violations = checker.check_register_usage(0x1000, 0x1010, "nop", {"rbx", "rax"})

        expect(len(violations) == 1)
        expect(violations[0].invariant_name == "callee_saved_preservation")


class TestControlFlowPreservationChecker:
    """Test ControlFlowPreservationChecker."""

    def test_successor_preservation_pass(self):
        """Check preserves successors."""
        mock_binary = _Binary()
        checker = ControlFlowPreservationChecker(mock_binary)

        violations = checker.check_successor_preservation(
            0x1000,
            0x1010,
            [0x1100, 0x1200],
            [0x1100, 0x1200],
        )
        expect(len(violations) == 0)

    def test_missing_successor(self):
        """Check detects missing successor."""
        mock_binary = _Binary()
        checker = ControlFlowPreservationChecker(mock_binary)

        violations = checker.check_successor_preservation(
            0x1000,
            0x1010,
            [0x1100, 0x1200],
            [0x1100],
        )
        expect(len(violations) == 1)
        expect(violations[0].invariant_name == "control_flow_preservation")

    def test_extra_successor(self):
        """Check detects extra successor."""
        mock_binary = _Binary()
        checker = ControlFlowPreservationChecker(mock_binary)

        violations = checker.check_successor_preservation(
            0x1000,
            0x1010,
            [0x1100],
            [0x1100, 0x1200],
        )
        expect(len(violations) == 1)


class TestSemanticInvariantChecker:
    """Test SemanticInvariantChecker."""

    def test_check_mutation_pass(self):
        """Check mutation passes all invariants."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        checker = SemanticInvariantChecker(mock_binary)
        violations = checker.check_mutation(
            MutationRegion(
                **{MUTATION_NAME_KEY: "nop"},
                start_address=0x1000,
                end_address=0x1010,
                original_bytes=b"\x90" * 16,
                mutated_bytes=b"\x90" * 16,
            )
        )
        expect(len(violations) == 0)

    def test_invariant_summary(self):
        """Get invariant summary."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

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

        expect(summary["total_violations"] == 1)
        expect(summary["by_severity"]["error"] == 1)
        expect(not (summary["passed"] is not False))


class TestMutationRegion:
    """Test MutationRegion dataclass."""

    def test_region_creation(self):
        """Create a mutation region."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\xcc" * 16,
            **{MUTATION_NAME_KEY: "nop"},
        )
        expect(region.start_address == _EXPECTED_REGION_START_ADDRESS_4096)
        expect(getattr(region, MUTATION_NAME_KEY) == "nop")

    def test_region_to_dict(self):
        """Convert region to dictionary."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\xcc" * 16,
            **{MUTATION_NAME_KEY: "nop"},
            function_address=0x1000,
        )
        d = region.to_dict()
        expect(d["start_address"] == _EXPECTED_D_START_ADDRESS_4096)
        expect(d["original_bytes"] == "90" * 16)
        expect(d["mutated_bytes"] == "cc" * 16)


class TestSemanticValidationReport:
    """Test SemanticValidationReport."""

    def test_report_creation(self):
        """Create a validation report."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\x90" * 16,
            **{MUTATION_NAME_KEY: "nop"},
        )
        result = SemanticValidationResult(
            region=region,
            status=ValidationResultStatus.PASS,
        )
        report = SemanticValidationReport(
            binary_path="test-data/test",
            timestamp="2024-01-01T00:00:00",
            mode=ValidationMode.STANDARD,
            results=[result],
        )

        expect(report.summary["total_mutations"] == 1)
        expect(report.summary["passed"] == 1)
        expect(report.summary["overall_status"] == "pass")

    def test_report_to_json(self):
        """Convert report to JSON."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\x90" * 16,
            **{MUTATION_NAME_KEY: "nop"},
        )
        result = SemanticValidationResult(
            region=region,
            status=ValidationResultStatus.PASS,
        )
        report = SemanticValidationReport(
            binary_path="test-data/test",
            timestamp="2024-01-01T00:00:00",
            mode=ValidationMode.STANDARD,
            results=[result],
        )

        json_str = report.to_json()
        expect(not ('"total_mutations"' not in json_str))
        expect(not ('"status": "pass"' not in json_str))

    def test_report_write_load(self, tmp_path):
        """Write and load report."""
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\x90" * 16,
            **{MUTATION_NAME_KEY: "nop"},
        )
        result = SemanticValidationResult(
            region=region,
            status=ValidationResultStatus.PASS,
        )
        report = SemanticValidationReport(
            binary_path="test-data/test",
            timestamp="2024-01-01T00:00:00",
            mode=ValidationMode.STANDARD,
            results=[result],
        )

        report_path = tmp_path / "report.json"
        report.write_report(report_path)

        loaded = SemanticValidationReport.load_report(report_path)
        expect(loaded.binary_path == "test-data/test")
        expect(loaded.mode == ValidationMode.STANDARD)


class TestSemanticValidator:
    """Test SemanticValidator."""

    def test_validator_creation(self):
        """Create a semantic validator."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        validator = SemanticValidator(mock_binary, ValidationMode.FAST)
        expect(validator.mode == ValidationMode.FAST)
        expect(validator.invariant_checker is not None)

    def test_validate_mutation_pass(self):
        """Validate a passing mutation."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}
        mock_binary.path = "test-data/test"

        validator = SemanticValidator(mock_binary)
        region = MutationRegion(
            start_address=0x1000,
            end_address=0x1010,
            original_bytes=b"\x90" * 16,
            mutated_bytes=b"\x90" * 16,
            **{MUTATION_NAME_KEY: "nop"},
        )

        result = validator.validate_mutation(region)
        expect(result.status == ValidationResultStatus.PASS)

    def test_validate_mutations(self):
        """Validate multiple mutations."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}
        mock_binary.path = "test-data/test"

        validator = SemanticValidator(mock_binary)
        regions = [
            MutationRegion(
                start_address=0x1000,
                end_address=0x1010,
                original_bytes=b"\x90" * 16,
                mutated_bytes=b"\x90" * 16,
                **{MUTATION_NAME_KEY: "nop"},
            ),
            MutationRegion(
                start_address=0x2000,
                end_address=0x2010,
                original_bytes=b"\x90" * 16,
                mutated_bytes=b"\x90" * 16,
                **{MUTATION_NAME_KEY: "nop"},
            ),
        ]

        report = validator.validate_mutations(regions)
        expect(report.summary["total_mutations"] == _EXPECTED_REPORT_SUMMARY_TOTAL_MUTATIONS_2)
        expect(report.summary["passed"] == _EXPECTED_REPORT_SUMMARY_PASSED_2)


class TestValidateSemanticEquivalence:
    """Test convenience function."""

    def test_convenience_function(self):
        """Test validate_semantic_equivalence function."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}
        mock_binary.path = "test-data/test"

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

        expect(not ("summary" not in report))
        expect(report["summary"]["total_mutations"] == 1)


class TestValidationModes:
    """Test validation modes."""

    def test_fast_mode(self):
        """Fast mode should skip symbolic."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        validator = SemanticValidator(mock_binary, ValidationMode.FAST)
        expect(validator.mode == ValidationMode.FAST)

    def test_standard_mode(self):
        """Standard mode."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        validator = SemanticValidator(mock_binary, ValidationMode.STANDARD)
        expect(validator.mode == ValidationMode.STANDARD)

    def test_thorough_mode(self):
        """Thorough mode."""
        mock_binary = _Binary()
        mock_binary.arch_info = {"arch": "x86_64", "bits": 64}

        validator = SemanticValidator(mock_binary, ValidationMode.THOROUGH)
        expect(validator.mode == ValidationMode.THOROUGH)


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
        expect(not (obs.register_matches["rax"] is not True))
        expect(not (obs.stack_delta_match is not True))

    def test_observable_to_dict(self):
        """Convert observable to dictionary."""
        obs = ObservableComparison(
            register_matches={"rax": False},
            register_values={"rax": (0x1234, 0x5678)},
            stack_delta_match=False,
            successor_match=True,
        )
        d = obs.to_dict()
        expect(not ("register_matches" not in d))
        expect(not ("register_values" not in d))
        expect(not (d["stack_delta_match"] is not False))
