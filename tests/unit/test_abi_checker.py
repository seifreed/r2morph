"""
Tests for ABI invariant checking.

These tests verify:
- Stack alignment checking for x86_64
- Red zone validation for System V ABI
- Shadow space validation for Windows x64
- Callee-saved register preservation
- Platform/arch-specific ABI rules
"""

import importlib

from r2morph.analysis.abi_checker import (
    ABI_SPECS,
    ABIChecker,
    ABIType,
    ABIViolationType,
    detect_abi,
)
from tests.utils.assertions import expect

_EXPECTED_ABI_RED_ZONE_SIZE_128 = 128
_EXPECTED_ABI_SHADOW_SPACE_SIZE_32 = 32
_EXPECTED_ABI_STACK_ALIGNMENT_16 = 16
_EXPECTED_CHECKER_ABI_SHADOW_SPACE_SIZE_32 = 32
_EXPECTED_SPEC_RED_ZONE_SIZE_128 = 128
_EXPECTED_SPEC_SHADOW_SPACE_SIZE_32 = 32
_EXPECTED_SPEC_STACK_ALIGNMENT_16 = 16
_EXPECTED_SPEC_STACK_ALIGNMENT_16_2 = 16
_EXPECTED_SPEC_STACK_ALIGNMENT_16_3 = 16


class MockBinary:
    """Mock binary for testing."""

    def __init__(self, arch_info, disasm=None):
        self._arch_info = arch_info
        self._disasm = disasm or []

    def get_arch_info(self):
        return self._arch_info

    def get_function_disasm(self, address):
        return self._disasm


class TestABISpecs:
    """Test ABI specification definitions."""

    def test_x86_64_sysv_spec(self):
        """x86_64 System V ABI has correct values."""
        spec = ABI_SPECS["x86_64_sysv"]
        expect(spec.abi_type == ABIType.X86_64_SYSTEM_V)
        expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_16)
        expect(spec.red_zone_size == _EXPECTED_SPEC_RED_ZONE_SIZE_128)
        expect(spec.shadow_space_size == 0)
        expect(not ("rbx" not in spec.callee_saved_regs))
        expect(not ("r12" not in spec.callee_saved_regs))
        expect(not ("rdi" not in spec.param_regs))

    def test_x86_64_windows_spec(self):
        """x86_64 Windows ABI has correct values."""
        spec = ABI_SPECS["x86_64_windows"]
        expect(spec.abi_type == ABIType.X86_64_WINDOWS)
        expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_16_2)
        expect(spec.red_zone_size == 0)
        expect(spec.shadow_space_size == _EXPECTED_SPEC_SHADOW_SPACE_SIZE_32)
        expect(not ("rbx" not in spec.callee_saved_regs))
        expect(not ("rdi" not in spec.callee_saved_regs))
        expect(not ("rcx" not in spec.param_regs))

    def test_arm64_aapcs_spec(self):
        """ARM64 AAPCS has correct values."""
        spec = ABI_SPECS["arm64_aapcs"]
        expect(spec.abi_type == ABIType.ARM64_AAPCS)
        expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_16_3)
        expect(spec.red_zone_size == 0)
        expect(not ("x19" not in spec.callee_saved_regs))
        expect(not ("x0" not in spec.param_regs))


class TestDetectABI:
    """Test ABI detection from binary."""

    def test_detect_x86_64_sysv(self):
        """Detect x86_64 System V ABI from ELF binary."""
        mock_binary = MockBinary({"arch": "x86", "bits": 64, "platform": "linux"})

        abi = detect_abi(mock_binary)
        expect(abi.abi_type == ABIType.X86_64_SYSTEM_V)
        expect(abi.stack_alignment == _EXPECTED_ABI_STACK_ALIGNMENT_16)
        expect(abi.red_zone_size == _EXPECTED_ABI_RED_ZONE_SIZE_128)

    def test_detect_x86_64_windows(self):
        """Detect x86_64 Windows ABI from PE binary."""
        mock_binary = MockBinary({"arch": "x86", "bits": 64, "platform": "windows"})

        abi = detect_abi(mock_binary)
        expect(abi.abi_type == ABIType.X86_64_WINDOWS)
        expect(abi.shadow_space_size == _EXPECTED_ABI_SHADOW_SPACE_SIZE_32)

    def test_detect_arm64(self):
        """Detect ARM64 AAPCS."""
        mock_binary = MockBinary({"arch": "aarch64", "bits": 64, "platform": "linux"})

        abi = detect_abi(mock_binary)
        expect(abi.abi_type == ABIType.ARM64_AAPCS)

    def test_detect_arm32(self):
        """Detect ARM32 AAPCS."""
        mock_binary = MockBinary({"arch": "arm", "bits": 32, "platform": "linux"})

        abi = detect_abi(mock_binary)
        expect(abi.abi_type == ABIType.ARM32_AAPCS)


class TestStackAlignment:
    """Test stack alignment checking."""

    def test_aligned_stack_no_violation(self):
        """No violation when stack is properly aligned at call."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "push rbp"},
                {"offset": 0x1002, "disasm": "mov rbp, rsp"},
                {"offset": 0x1005, "disasm": "sub rsp, 0x8"},
                {"offset": 0x1009, "disasm": "call 0x2000"},
                {"offset": 0x100E, "disasm": "add rsp, 0x8"},
                {"offset": 0x1012, "disasm": "pop rbp"},
                {"offset": 0x1013, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        violations = checker.check_stack_alignment(0x1000)
        expect(len(violations) == 0)

    def test_misaligned_stack_at_call(self):
        """Violation when stack is misaligned at call."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "push rbp"},
                {"offset": 0x1002, "disasm": "mov rbp, rsp"},
                {"offset": 0x1005, "disasm": "call 0x2000"},
            ],
        )

        checker = ABIChecker(mock_binary)
        violations = checker.check_stack_alignment(0x1000)
        expect(len(violations) == 1)
        expect(violations[0].violation_type == ABIViolationType.STACK_ALIGNMENT)

    def test_stack_alignment_windows(self):
        """Windows x64 ABI also requires 16-byte alignment."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "windows"},
            [
                {"offset": 0x1000, "disasm": "push rbp"},
                {"offset": 0x1002, "disasm": "call 0x2000"},
            ],
        )

        checker = ABIChecker(mock_binary)
        expect(checker.abi.abi_type == ABIType.X86_64_WINDOWS)
        violations = checker.check_stack_alignment(0x1000)
        expect(len(violations) == 1)


class TestRedZone:
    """Test red zone checking."""

    def test_red_zone_no_clobber(self):
        """No violation when mutation fits in red zone."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "mov rax, rbx"},
                {"offset": 0x1003, "disasm": "add rax, 1"},
                {"offset": 0x1007, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        mutations = [(0x1000, 0x1003)]
        violations = checker.check_red_zone(0x1000, mutations)
        expect(len(violations) == 0)

    def test_red_zone_exceeded_in_leaf(self):
        """Violation when mutation exceeds red zone in leaf function."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "mov rax, rbx"},
                {"offset": 0x1003, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        mutations = [(0x1000, 0x1000 + 200)]
        violations = checker.check_red_zone(0x1000, mutations)
        expect(len(violations) == 1)
        expect(violations[0].violation_type == ABIViolationType.RED_ZONE_CLOBBER)

    def test_red_zone_not_applicable_to_windows(self):
        """No red zone checking for Windows ABI."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "windows"},
            [
                {"offset": 0x1000, "disasm": "mov rax, rbx"},
                {"offset": 0x1003, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        mutations = [(0x1000, 0x1000 + 200)]
        violations = checker.check_red_zone(0x1000, mutations)
        expect(len(violations) == 0)

    def test_red_zone_not_applicable_to_non_leaf(self):
        """No red zone violation for non-leaf functions (those with calls)."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "call other_func"},
                {"offset": 0x1005, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        mutations = [(0x1000, 0x1000 + 200)]
        violations = checker.check_red_zone(0x1000, mutations)
        expect(len(violations) == 0)


class TestShadowSpace:
    """Test shadow space checking for Windows x64."""

    def test_shadow_space_allocated(self):
        """No violation when shadow space is properly allocated."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "windows"},
            [
                {"offset": 0x1000, "disasm": "sub rsp, 0x38"},
                {"offset": 0x1004, "disasm": "call 0x2000"},
                {"offset": 0x1009, "disasm": "add rsp, 0x38"},
                {"offset": 0x100D, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        expect(checker.abi.shadow_space_size == _EXPECTED_CHECKER_ABI_SHADOW_SPACE_SIZE_32)
        violations = checker.check_shadow_space(0x1000)
        expect(len(violations) == 0)

    def test_shadow_space_missing_no_push(self):
        """Violation when shadow space not allocated before call."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "windows"},
            [
                {"offset": 0x1000, "disasm": "mov rcx, rax"},
                {"offset": 0x1003, "disasm": "call 0x2000"},
                {"offset": 0x1008, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        violations = checker.check_shadow_space(0x1000)
        expect(len(violations) == 1)
        expect(violations[0].violation_type == ABIViolationType.SHADOW_SPACE_VIOLATION)

    def test_shadow_space_not_applicable_to_linux(self):
        """No shadow space checking for Linux ABI."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "call 0x2000"},
                {"offset": 0x1005, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        violations = checker.check_shadow_space(0x1000)
        expect(len(violations) == 0)


class TestCalleeSaved:
    """Test callee-saved register preservation."""

    def test_callee_saved_preserved(self):
        """No violation when callee-saved registers are properly saved."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "push rbx"},
                {"offset": 0x1002, "disasm": "push r12"},
                {"offset": 0x1004, "disasm": "mov rbx, rax"},
                {"offset": 0x1007, "disasm": "mov r12, rdx"},
                {"offset": 0x100A, "disasm": "pop r12"},
                {"offset": 0x100C, "disasm": "pop rbx"},
                {"offset": 0x100E, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        violations = checker.check_callee_saved(0x1000)
        expect(len(violations) == 0)

    def test_callee_saved_clobbered(self):
        """Violation when callee-saved register modified without save."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "mov rbx, rax"},
                {"offset": 0x1003, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        violations = checker.check_callee_saved(0x1000)
        expect(not (len(violations) < 1))
        expect(any(v.violation_type == ABIViolationType.CALLEE_SAVED_CLOBBER for v in violations))

    def test_callee_saved_arm64(self):
        """ARM64 callee-saved register preservation."""
        mock_binary = MockBinary(
            {"arch": "aarch64", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "stp x29, x30, [sp, #-16]!"},
                {"offset": 0x1004, "disasm": "mov x0, x1"},
                {"offset": 0x1008, "disasm": "ldp x29, x30, [sp], #16"},
                {"offset": 0x100C, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        violations = checker.check_callee_saved(0x1000)
        expect(len(violations) == 0)


class TestABICheckerIntegration:
    """Integration tests for ABIChecker."""

    def test_check_all_no_violations(self):
        """No violations for well-formed function."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "push rbp"},
                {"offset": 0x1002, "disasm": "mov rbp, rsp"},
                {"offset": 0x1005, "disasm": "push rbx"},
                {"offset": 0x1007, "disasm": "push r12"},
                {"offset": 0x100A, "disasm": "sub rsp, 0x8"},
                {"offset": 0x100E, "disasm": "call other_func"},
                {"offset": 0x1013, "disasm": "add rsp, 0x8"},
                {"offset": 0x1017, "disasm": "pop r12"},
                {"offset": 0x1019, "disasm": "pop rbx"},
                {"offset": 0x101B, "disasm": "pop rbp"},
                {"offset": 0x101C, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)
        violations = checker.check_all(0x1000)
        stack_violations = [v for v in violations if v.violation_type == ABIViolationType.STACK_ALIGNMENT]
        expect(len(stack_violations) == 0)

    def test_validate_mutation_introduces_violation(self):
        """Validation detects new violations introduced by mutation."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "mov rbx, rax"},
                {"offset": 0x1003, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)

        original_violations = []

        result = checker.validate_mutation(0x1000, original_violations)

        expect(not ("valid" not in result))
        expect(not ("violations" not in result))
        expect(not ("new_violations" not in result))

    def test_validate_mutation_preserves_existing(self):
        """Validation preserves existing violations as expected."""
        mock_binary = MockBinary(
            {"arch": "x86", "bits": 64, "platform": "linux"},
            [
                {"offset": 0x1000, "disasm": "push rbp"},
                {"offset": 0x1002, "disasm": "pop rbp"},
                {"offset": 0x1004, "disasm": "ret"},
            ],
        )

        checker = ABIChecker(mock_binary)

        a_b_i_violation = importlib.import_module("r2morph.analysis.abi_checker").ABIViolation

        existing_violation = a_b_i_violation(
            violation_type=ABIViolationType.STACK_ALIGNMENT,
            description="Pre-existing issue",
            location=0x1000,
        )

        result = checker.validate_mutation(0x1000, [existing_violation])

        expect(len(result["new_violations"]) == 0)


class TestABIViolationTypes:
    """Test ABIViolationType enum values."""

    def test_violation_types_exist(self):
        """All violation types should have string values."""
        expect(ABIViolationType.STACK_ALIGNMENT.value == "stack_alignment")
        expect(ABIViolationType.RED_ZONE_CLOBBER.value == "red_zone_clobber")
        expect(ABIViolationType.SHADOW_SPACE_VIOLATION.value == "shadow_space_violation")
        expect(ABIViolationType.CALLEE_SAVED_CLOBBER.value == "callee_saved_clobber")
        expect(ABIViolationType.CALLING_CONVENTION.value == "calling_convention")
