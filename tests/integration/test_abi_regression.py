"""
Regression tests for ABI invariant enforcement.

Tests for Issue #5:
- All mutation passes respect ABI invariants
- Violations are detected and reported
- Platform-specific rules are enforced
- Violations can block output
"""

import pytest

from r2morph.analysis.abi_checker import (
    ABI_SPECS,
    ABIType,
    ABIViolation,
    ABIViolationType,
    detect_abi,
)
from r2morph.mutations.abi_aware_base import (
    ABIAwareMutationPass,
    ABIResult,
    ABIValidationError,
)
from r2morph.mutations.abi_hook import (
    ABICheckOptions,
    ABICheckResult,
    ABIMutationHook,
    ABISnapshot,
    ABIViolationAction,
    create_abi_hook,
)
from tests.utils.assertions import expect

_EXPECTED_LEN_RESULT_BLOCKED_FUNCTIONS_2 = 2
_EXPECTED_RESULT_NEW_VIOLATIONS_5 = 5
_EXPECTED_RESULT_VIOLATIONS_AFTER_5 = 5
_EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096 = 0x1000
_EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096_2 = 0x1000
_EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096_3 = 0x1000
_EXPECTED_SPEC_RED_ZONE_SIZE_128 = 128
_EXPECTED_SPEC_SHADOW_SPACE_SIZE_32 = 32
_EXPECTED_SPEC_STACK_ALIGNMENT_16 = 16
_EXPECTED_SPEC_STACK_ALIGNMENT_16_2 = 16
_EXPECTED_SPEC_STACK_ALIGNMENT_16_3 = 16


class MockBinary:
    """Mock binary for testing."""

    def __init__(self, arch="x86_64", platform="linux", bits=64):
        self._arch = arch
        self._platform = platform
        self._bits = bits
        self._analyzed = False
        self._functions = []

    def is_analyzed(self):
        return self._analyzed

    def analyze(self):
        self._analyzed = True

    def get_arch_info(self):
        return {"arch": self._arch, "platform": self._platform, "bits": self._bits}

    def get_functions(self):
        return self._functions

    def get_function_disasm(self, addr):
        return []


class TestABIMutationHook:
    """Tests for ABIMutationHook."""

    def test_init_default_action(self):
        """Test default action is WARN."""
        binary = MockBinary()
        hook = ABIMutationHook(binary)

        expect(hook.action == ABIViolationAction.WARN)
        expect(not (hook.check_stack_alignment is not True))
        expect(not (hook.check_callee_saved is not True))

    def test_init_block_action(self):
        """Test BLOCK action initialization."""
        binary = MockBinary()
        hook = ABIMutationHook(binary, action=ABIViolationAction.BLOCK)

        expect(hook.action == ABIViolationAction.BLOCK)

    def test_init_skip_action(self):
        """Test SKIP action initialization."""
        binary = MockBinary()
        hook = ABIMutationHook(binary, action=ABIViolationAction.SKIP)

        expect(hook.action == ABIViolationAction.SKIP)

    def test_init_custom_checks(self):
        """Test custom check configuration."""
        binary = MockBinary()
        hook = ABIMutationHook(
            binary,
            options=ABICheckOptions(
                stack_alignment=True,
                callee_saved=False,
                red_zone=True,
                shadow_space=False,
            ),
        )

        expect(not (hook.check_stack_alignment is not True))
        expect(not (hook.check_callee_saved is not False))
        expect(not (hook.check_red_zone is not True))
        expect(not (hook.check_shadow_space is not False))

    def test_snapshot_function(self):
        """Test function snapshot creation."""
        binary = MockBinary()
        hook = ABIMutationHook(binary)

        snapshot = hook.snapshot_function(0x1000)

        expect(snapshot.function_address == _EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096)
        expect(isinstance(snapshot.violations, list))
        expect(isinstance(snapshot, ABISnapshot))

    def test_validate_function_no_violations(self):
        """Test validation with no violations."""
        binary = MockBinary()
        hook = ABIMutationHook(binary)

        hook.snapshot_function(0x1000)
        result = hook.validate_function(0x1000)

        expect(isinstance(result, ABICheckResult))
        expect(not (result.valid is not True))
        expect(len(result.new_violations) == 0)

    def test_validate_region(self):
        """Test region validation."""
        binary = MockBinary()
        hook = ABIMutationHook(binary)

        result = hook.validate_region(0x1000, 0x1100)

        expect(isinstance(result, ABICheckResult))

    def test_should_skip_mutation(self):
        """Test skip mutation logic."""
        binary = MockBinary()
        hook = ABIMutationHook(binary, action=ABIViolationAction.SKIP)

        expect(not (hook.should_skip_mutation(0x1000) is not False))

    def test_can_save_binary(self):
        """Test can_save_binary logic."""
        binary = MockBinary()
        hook = ABIMutationHook(binary)

        expect(not (hook.can_save_binary() is not True))

        hook_block = ABIMutationHook(binary, action=ABIViolationAction.BLOCK)
        expect(not (hook_block.can_save_binary() is not True))

    def test_get_diagnostics(self):
        """Test diagnostics output."""
        binary = MockBinary()
        hook = ABIMutationHook(binary)

        diagnostics = hook.get_diagnostics()

        expect(not ("abi_type" not in diagnostics))
        expect(not ("total_violations" not in diagnostics))
        expect(not ("checks_enabled" not in diagnostics))

    def test_reset(self):
        """Test reset functionality."""
        binary = MockBinary()
        hook = ABIMutationHook(binary)

        hook.snapshot_function(0x1000)
        hook.reset()

        expect(len(hook._snapshots) == 0)
        expect(len(hook._total_violations) == 0)


class TestABICheckResult:
    """Tests for ABICheckResult."""

    def test_valid_result(self):
        """Test valid result creation."""
        result = ABICheckResult(valid=True)

        expect(not (result.valid is not True))
        expect(len(result.violations) == 0)

    def test_invalid_result(self):
        """Test invalid result with violations."""
        violation = ABIViolation(
            violation_type=ABIViolationType.STACK_ALIGNMENT,
            description="Test violation",
            location=0x1000,
        )

        result = ABICheckResult(
            valid=False,
            violations=[violation],
            new_violations=[violation],
        )

        expect(not (result.valid is not False))
        expect(len(result.violations) == 1)


class TestABISnapshot:
    """Tests for ABISnapshot."""

    def test_snapshot_creation(self):
        """Test snapshot creation."""
        snapshot = ABISnapshot(
            function_address=0x1000,
            violations=[],
            stack_alignment_ok=True,
            callee_saved_ok=True,
            red_zone_ok=True,
            shadow_space_ok=True,
        )

        expect(snapshot.function_address == _EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096_2)
        expect(not (snapshot.stack_alignment_ok is not True))

    def test_snapshot_with_violations(self):
        """Test snapshot with violations."""
        violation = ABIViolation(
            violation_type=ABIViolationType.CALLEE_SAVED_CLOBBER,
            description="Test",
            location=0x1000,
        )

        snapshot = ABISnapshot(
            function_address=0x1000,
            violations=[violation],
            callee_saved_ok=False,
        )

        expect(len(snapshot.violations) == 1)
        expect(not (snapshot.callee_saved_ok is not False))


class TestFactoryFunction:
    """Tests for factory function."""

    def test_create_abi_hook_default(self):
        """Test default hook creation."""
        binary = MockBinary()
        hook = create_abi_hook(binary)

        expect(hook.action == ABIViolationAction.WARN)

    def test_create_abi_hook_strict(self):
        """Test strict hook creation."""
        binary = MockBinary()
        hook = create_abi_hook(binary, strict=True)

        expect(hook.action == ABIViolationAction.BLOCK)

    def test_create_abi_hook_custom_checks(self):
        """Test custom checks."""
        binary = MockBinary()
        hook = create_abi_hook(
            binary,
            checks=["stack_alignment", "callee_saved"],
        )

        expect(not (hook.check_stack_alignment is not True))
        expect(not (hook.check_callee_saved is not True))
        expect(not (hook.check_red_zone is not False))


class TestABIAwareMutationPass:
    """Tests for ABIAwareMutationPass."""

    def test_init(self):
        """Test pass initialization."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        p = TestPass("test", enforce_abi=True)

        expect(not (p.enforce_abi is not True))
        expect(p.abi_action == ABIViolationAction.WARN)

    def test_init_disabled(self):
        """Test pass with ABI disabled."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        p = TestPass("test", enforce_abi=False)

        expect(not (p.enforce_abi is not False))

    def test_init_block_action(self):
        """Test pass with BLOCK action."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        p = TestPass("test", abi_action="block")

        expect(p.abi_action == ABIViolationAction.BLOCK)

    def test_snapshot_abi(self):
        """Test ABI snapshot method."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        binary = MockBinary()
        p = TestPass("test")
        p._abi_hook = ABIMutationHook(binary)

        snapshot = p.snapshot_abi(0x1000)

        expect(snapshot is not None)
        expect(snapshot.function_address == _EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096_3)

    def test_snapshot_abi_disabled(self):
        """Test snapshot when ABI disabled."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        p = TestPass("test", enforce_abi=False)

        snapshot = p.snapshot_abi(0x1000)

        expect(not (snapshot is not None))

    def test_validate_abi(self):
        """Test validate_abi method."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        binary = MockBinary()
        p = TestPass("test")
        p._abi_hook = ABIMutationHook(binary)
        p._abi_result = ABIResult(valid=True)

        result = p.validate_abi(0x1000)

        expect(result is not None)

    def test_validate_abi_disabled(self):
        """Test validate_abi when ABI disabled."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        p = TestPass("test", enforce_abi=False)

        result = p.validate_abi(0x1000)

        expect(not (result is not None))

    def test_can_continue_after_abi_check(self):
        """Test can_continue_after_abi_check."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        binary = MockBinary()
        p = TestPass("test")
        p._abi_hook = ABIMutationHook(binary)

        expect(not (p.can_continue_after_abi_check(0x1000) is not True))

    def test_get_abi_diagnostics(self):
        """Test get_abi_diagnostics."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        binary = MockBinary()
        p = TestPass("test")
        p._abi_hook = ABIMutationHook(binary)

        diagnostics = p.get_abi_diagnostics()

        expect(not ("abi_type" not in diagnostics))

    def test_get_abi_result(self):
        """Test get_abi_result."""

        class TestPass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        p = TestPass("test")
        p._abi_result = ABIResult(valid=True)

        result = p.get_abi_result()

        expect(result is not None)
        expect(not (result.valid is not True))


class TestABIValidationError:
    """Tests for ABIValidationError."""

    def test_error_creation(self):
        """Test error creation."""
        error = ABIValidationError("Test error")

        expect(str(error) == "Test error")
        expect(error.violations == [])

    def test_error_with_violations(self):
        """Test error with violations."""
        violation = ABIViolation(
            violation_type=ABIViolationType.STACK_ALIGNMENT,
            description="Test",
            location=0x1000,
        )

        error = ABIValidationError("Test error", violations=[violation])

        expect(len(error.violations) == 1)


@pytest.mark.integration
class TestABIRegressionX8664:
    """Regression tests for x86_64 ABI."""

    def test_sysv_abi_spec(self):
        """Test System V ABI specification."""
        spec = ABI_SPECS["x86_64_sysv"]

        expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_16)
        expect(spec.red_zone_size == _EXPECTED_SPEC_RED_ZONE_SIZE_128)
        expect(spec.shadow_space_size == 0)
        expect(not ("rbx" not in spec.callee_saved_regs))
        expect(not ("rdi" not in spec.param_regs))

    def test_windows_abi_spec(self):
        """Test Windows x64 ABI specification."""
        spec = ABI_SPECS["x86_64_windows"]

        expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_16_2)
        expect(spec.red_zone_size == 0)
        expect(spec.shadow_space_size == _EXPECTED_SPEC_SHADOW_SPACE_SIZE_32)
        expect(not ("rbx" not in spec.callee_saved_regs))
        expect(not ("rcx" not in spec.param_regs))

    def test_detect_abi_x86_64_linux(self):
        """Test ABI detection for x86_64 Linux."""
        binary = MockBinary(arch="x86_64", platform="linux", bits=64)
        spec = detect_abi(binary)

        expect(spec.abi_type == ABIType.X86_64_SYSTEM_V)

    def test_detect_abi_x86_64_windows(self):
        """Test ABI detection for x86_64 Windows."""
        binary = MockBinary(arch="x86_64", platform="windows", bits=64)
        spec = detect_abi(binary)

        expect(spec.abi_type == ABIType.X86_64_WINDOWS)

    def test_detect_abi_arm64(self):
        """Test ABI detection for ARM64."""
        binary = MockBinary(arch="aarch64", platform="linux", bits=64)
        spec = detect_abi(binary)

        expect(spec.abi_type == ABIType.ARM64_AAPCS)


@pytest.mark.integration
class TestABIRegressionArm64:
    """Regression tests for ARM64 ABI."""

    def test_arm64_abi_spec(self):
        """Test ARM64 AAPCS specification."""
        spec = ABI_SPECS["arm64_aapcs"]

        expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_16_3)
        expect(spec.red_zone_size == 0)
        expect(spec.shadow_space_size == 0)
        expect(not ("x19" not in spec.callee_saved_regs))
        expect(not ("x0" not in spec.param_regs))

    def test_arm64_callee_saved(self):
        """Test ARM64 callee-saved register checks."""
        spec = ABI_SPECS["arm64_aapcs"]

        expected_saved = ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30"]

        for reg in expected_saved:
            expect(not (reg not in spec.callee_saved_regs), f"{reg} should be callee-saved")


@pytest.mark.integration
class TestABIIntegrationWithMutations:
    """Integration tests for ABI with mutation passes."""

    def test_abi_hook_lifecycle(self):
        """Test complete ABI hook lifecycle."""
        binary = MockBinary(arch="x86_64", platform="linux", bits=64)
        hook = ABIMutationHook(binary, action=ABIViolationAction.WARN)

        snapshot = hook.snapshot_function(0x1000)

        expect(snapshot is not None)

        result = hook.validate_function(0x1000)

        expect(isinstance(result, ABICheckResult))
        expect(not (result.valid is not True))

        diagnostics = hook.get_diagnostics()

        expect(not ("abi_type" not in diagnostics))
        expect(diagnostics["abi_type"] == "x86_64_sysv")

    def test_abi_hook_with_block_action(self):
        """Test hook with BLOCK action."""
        binary = MockBinary()
        hook = ABIMutationHook(binary, action=ABIViolationAction.BLOCK)

        hook.snapshot_function(0x1000)
        hook.validate_function(0x1000)

        expect(not (hook.can_save_binary() is not True))

    def test_multiple_functions(self):
        """Test ABI checking across multiple functions."""
        binary = MockBinary()
        hook = ABIMutationHook(binary)

        for addr in [0x1000, 0x2000, 0x3000]:
            hook.snapshot_function(addr)
            result = hook.validate_function(addr)
            expect(isinstance(result, ABICheckResult))

        expect(not (hook.total_violations < 0))

    def test_violation_accumulation(self):
        """Test that violations accumulate."""
        binary = MockBinary()
        hook = ABIMutationHook(binary)

        hook.snapshot_function(0x1000)
        hook.validate_function(0x1000)

        count1 = hook.total_violations

        hook.snapshot_function(0x2000)
        hook.validate_function(0x2000)

        count2 = hook.total_violations

        expect(not (count2 < count1))


class TestABIPassIntegration:
    """Tests for ABI pass integration."""

    def test_abi_result_creation(self):
        """Test ABIResult creation."""
        result = ABIResult(
            valid=True,
            violations_before=0,
            violations_after=0,
            new_violations=0,
            blocked_functions=[],
            diagnostics={},
        )

        expect(not (result.valid is not True))
        expect(result.violations_before == 0)
        expect(result.violations_after == 0)
        expect(result.new_violations == 0)
        expect(len(result.blocked_functions) == 0)

    def test_abi_result_with_violations(self):
        """Test ABIResult with violations."""
        result = ABIResult(
            valid=False,
            violations_before=0,
            violations_after=5,
            new_violations=5,
            blocked_functions=[0x1000, 0x2000],
            diagnostics={"abi_type": "x86_64_sysv"},
        )

        expect(not (result.valid is not False))
        expect(result.violations_after == _EXPECTED_RESULT_VIOLATIONS_AFTER_5)
        expect(result.new_violations == _EXPECTED_RESULT_NEW_VIOLATIONS_5)
        expect(len(result.blocked_functions) == _EXPECTED_LEN_RESULT_BLOCKED_FUNCTIONS_2)

    def test_abi_aware_pass_direct_instantiation(self):
        """Test direct instantiation of ABI-aware pass."""

        class ConcretePass(ABIAwareMutationPass):
            def apply_abi_aware(self, binary, abi_hook):
                return {"mutations": [], "mutations_applied": 0}

        p = ConcretePass(
            name="test_concrete",
            enforce_abi=True,
            abi_action="warn",
            abi_checks=["stack_alignment", "callee_saved"],
        )

        expect(not (p.enforce_abi is not True))
        expect(p.abi_action == ABIViolationAction.WARN)
        expect(p.abi_checks == ["stack_alignment", "callee_saved"])
