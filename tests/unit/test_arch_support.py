"""
Tests for ARM32, x86_32, and ARM64 architecture support.

Tests for architecture support:
- ARM32 NOP equivalents
- x86_32 NOP equivalents
- ARM64 NOP equivalents
- Caller-saved registers
- Architecture detection
"""

import pytest
import random
from unittest.mock import MagicMock, patch

from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.analysis.abi_checker import ABI_SPECS, ABIType
from r2morph.core.support import (
    PRODUCT_SUPPORT,
    classify_target_support,
    _normalize_architecture_name,
)


class TestArchitectureSupport:
    """Tests for architecture support matrix."""

    def test_x86_32_in_experimental(self):
        """Test x86_32 is in prolonged experimental architectures."""
        assert "x86" in PRODUCT_SUPPORT.prolonged_experimental_architectures

    def test_arm32_in_experimental(self):
        """Test ARM32 is in prolonged experimental architectures."""
        assert "arm32" in PRODUCT_SUPPORT.prolonged_experimental_architectures

    def test_arm64_in_experimental(self):
        """Test ARM64 is in prolonged experimental architectures."""
        assert "arm64" in PRODUCT_SUPPORT.prolonged_experimental_architectures

    def test_classify_x86_32_target(self):
        """Test x86_32 target classification."""
        result = classify_target_support("ELF", "x86", 32)

        assert result["tier"] == "prolonged-experimental"
        assert result["architecture"] == "x86"

    def test_classify_arm32_target(self):
        """Test ARM32 target classification."""
        result = classify_target_support("ELF", "arm", 32)

        assert result["tier"] == "unsupported"
        assert "architecture" in result

    def test_classify_arm64_target(self):
        """Test ARM64 target classification."""
        result = classify_target_support("ELF", "arm64", 64)

        assert result["tier"] == "prolonged-experimental"
        assert result["architecture"] == "arm64"

    def test_normalize_x86_32(self):
        """Test x86_32 architecture normalization."""
        assert _normalize_architecture_name("x86", 32) == "x86"
        assert _normalize_architecture_name("i386", 32) == "i386"
        assert _normalize_architecture_name("i686", 32) == "i686"

    def test_normalize_x86_64(self):
        """Test x86_64 architecture normalization."""
        assert _normalize_architecture_name("x86_64", 64) == "x86_64"
        assert _normalize_architecture_name("amd64", 64) == "x86_64"


class TestNopInsertionArchitecture:
    """Tests for NOP insertion architecture support."""

    def test_x86_32_nop_equivalents_exist(self):
        """Test x86_32 NOP equivalents are defined."""
        config = {"seed": 42}
        p = NopInsertionPass(config=config)

        assert "x86" in p.NOP_EQUIVALENTS_BASE
        assert len(p.NOP_EQUIVALENTS_BASE["x86"]) > 0

    def test_x86_64_nop_equivalents_exist(self):
        """Test x86_64 NOP equivalents are defined."""
        config = {"seed": 42}
        p = NopInsertionPass(config=config)

        assert "x86_64" in p.NOP_EQUIVALENTS_BASE
        assert len(p.NOP_EQUIVALENTS_BASE["x86_64"]) > 0

    def test_arm32_nop_equivalents_exist(self):
        """Test ARM32 NOP equivalents are defined."""
        config = {"seed": 42}
        p = NopInsertionPass(config=config)

        assert "arm32" in p.NOP_EQUIVALENTS_BASE
        assert len(p.NOP_EQUIVALENTS_BASE["arm32"]) > 0

    def test_arm64_nop_equivalents_exist(self):
        """Test ARM64 NOP equivalents are defined."""
        config = {"seed": 42}
        p = NopInsertionPass(config=config)

        assert "arm64" in p.NOP_EQUIVALENTS_BASE
        assert len(p.NOP_EQUIVALENTS_BASE["arm64"]) > 0

    def test_x86_32_caller_saved_registers(self):
        """Test x86_32 caller-saved registers."""
        p = NopInsertionPass()

        assert "eax" in p.CALLER_SAVED_32BIT
        assert "ecx" in p.CALLER_SAVED_32BIT
        assert "edx" in p.CALLER_SAVED_32BIT
        assert "ebx" not in p.CALLER_SAVED_32BIT
        assert "esi" not in p.CALLER_SAVED_32BIT

    def test_arm32_caller_saved_registers(self):
        """Test ARM32 caller-saved registers."""
        p = NopInsertionPass()

        assert "r0" in p.CALLER_SAVED_ARM32
        assert "r1" in p.CALLER_SAVED_ARM32
        assert "r2" in p.CALLER_SAVED_ARM32
        assert "r3" in p.CALLER_SAVED_ARM32
        assert "r12" in p.CALLER_SAVED_ARM32
        assert "lr" in p.CALLER_SAVED_ARM32
        assert "r4" not in p.CALLER_SAVED_ARM32
        assert "r5" not in p.CALLER_SAVED_ARM32

    def test_arm64_caller_saved_registers(self):
        """Test ARM64 caller-saved registers."""
        p = NopInsertionPass()

        assert "x0" in p.CALLER_SAVED_ARM64
        assert "x1" in p.CALLER_SAVED_ARM64
        assert "x2" in p.CALLER_SAVED_ARM64
        assert "x3" in p.CALLER_SAVED_ARM64
        assert "x30" in p.CALLER_SAVED_ARM64
        assert "x19" not in p.CALLER_SAVED_ARM64
        assert "x20" not in p.CALLER_SAVED_ARM64

    def test_get_arch_key_x86_32(self):
        """Test architecture key for x86_32."""
        p = NopInsertionPass()

        assert p._get_arch_key("x86", 32) == "x86"
        assert p._get_arch_key("x86", 64) == "x86_64"

    def test_get_arch_key_arm32(self):
        """Test architecture key for ARM32."""
        p = NopInsertionPass()

        assert p._get_arch_key("arm", 32) == "arm32"
        assert p._get_arch_key("arm", 64) == "arm64"

    def test_get_caller_saved_x86_32(self):
        """Test getting caller-saved registers for x86_32."""
        p = NopInsertionPass()

        regs = p._get_caller_saved("x86", 32)

        assert "eax" in regs
        assert "ecx" in regs
        assert "edx" in regs

    def test_get_caller_saved_arm32(self):
        """Test getting caller-saved registers for ARM32."""
        p = NopInsertionPass()

        regs = p._get_caller_saved("arm", 32)

        assert "r0" in regs
        assert "r1" in regs
        assert "r2" in regs
        assert "r3" in regs

    def test_get_caller_saved_arm64(self):
        """Test getting caller-saved registers for ARM64."""
        p = NopInsertionPass()

        regs = p._get_caller_saved("arm", 64)

        assert "x0" in regs
        assert "x1" in regs
        assert "x30" in regs


class TestArm32NopEquivalents:
    """Tests for ARM32 NOP equivalents content."""

    def test_arm32_mov_self_is_nop(self):
        """Test that mov r0, r0 is a NOP equivalent."""
        p = NopInsertionPass()

        arm32_nops = p.NOP_EQUIVALENTS_BASE["arm32"]

        assert "mov r0, r0" in arm32_nops
        assert "mov r1, r1" in arm32_nops
        assert "mov r2, r2" in arm32_nops

    def test_arm32_self_canceling_nop(self):
        """Test self-canceling operations are NOP equivalents."""
        p = NopInsertionPass()

        arm32_nops = p.NOP_EQUIVALENTS_BASE["arm32"]

        assert "add r0, r0, #0" in arm32_nops
        assert "sub r0, r0, #0" in arm32_nops
        assert "and r0, r0, r0" in arm32_nops

    def test_arm32_registers_complete(self):
        """Test ARM32 register list is complete."""
        p = NopInsertionPass()

        expected_regs = [
            "r0",
            "r1",
            "r2",
            "r3",
            "r4",
            "r5",
            "r6",
            "r7",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "sp",
            "lr",
            "pc",
        ]

        for reg in expected_regs:
            assert reg in p.REGISTERS_ARM32, f"Missing ARM32 register: {reg}"


class TestX8632NopEquivalents:
    """Tests for x86_32 NOP equivalents content."""

    def test_x86_32_xchg_self_is_nop(self):
        """Test that xchg eax, eax is a NOP equivalent."""
        p = NopInsertionPass()

        x86_nops = p.NOP_EQUIVALENTS_BASE["x86"]

        assert "xchg eax, eax" in x86_nops
        assert "xchg ebx, ebx" in x86_nops
        assert "xchg ecx, ecx" in x86_nops
        assert "xchg edx, edx" in x86_nops

    def test_x86_32_mov_self_is_nop(self):
        """Test that mov eax, eax is a NOP equivalent."""
        p = NopInsertionPass()

        x86_nops = p.NOP_EQUIVALENTS_BASE["x86"]

        assert "mov eax, eax" in x86_nops
        assert "mov ebx, ebx" in x86_nops
        assert "mov ecx, ecx" in x86_nops
        assert "mov edx, edx" in x86_nops
        assert "mov esi, esi" in x86_nops
        assert "mov edi, edi" in x86_nops

    def test_x86_32_lea_self_is_nop(self):
        """Test that lea eax, [eax] is a NOP equivalent."""
        p = NopInsertionPass()

        x86_nops = p.NOP_EQUIVALENTS_BASE["x86"]

        assert "lea eax, [eax]" in x86_nops
        assert "lea ebx, [ebx]" in x86_nops
        assert "lea ecx, [ecx]" in x86_nops
        assert "lea edx, [edx]" in x86_nops

    def test_x86_32_registers_complete(self):
        """Test x86_32 register list is complete."""
        p = NopInsertionPass()

        expected_regs = ["eax", "ebx", "ecx", "edx", "esi", "edi"]

        for reg in expected_regs:
            assert reg in p.REGISTERS_32BIT, f"Missing x86_32 register: {reg}"


class TestABISpecsArm32X8632:
    """Tests for ABI specs for ARM32 and x86_32."""

    def test_arm32_abi_spec_exists(self):
        """Test ARM32 ABI spec exists."""
        assert "arm32_aapcs" in ABI_SPECS

        spec = ABI_SPECS["arm32_aapcs"]

        assert spec.abi_type == ABIType.ARM32_AAPCS
        assert spec.stack_alignment == 8
        assert spec.red_zone_size == 0
        assert spec.shadow_space_size == 0

    def test_arm32_callee_saved_regs(self):
        """Test ARM32 callee-saved registers."""
        spec = ABI_SPECS["arm32_aapcs"]

        expected_saved = ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"]

        for reg in expected_saved:
            assert reg in spec.callee_saved_regs, f"Missing callee-saved: {reg}"

    def test_arm32_param_regs(self):
        """Test ARM32 parameter registers."""
        spec = ABI_SPECS["arm32_aapcs"]

        expected_params = ["r0", "r1", "r2", "r3"]

        for reg in expected_params:
            assert reg in spec.param_regs, f"Missing param register: {reg}"

    def test_x86_32_linux_abi_spec_exists(self):
        """Test x86_32 Linux ABI spec exists."""
        assert "x86_32_linux" in ABI_SPECS

        spec = ABI_SPECS["x86_32_linux"]

        assert spec.abi_type == ABIType.X86_32_LINUX
        assert spec.stack_alignment == 4
        assert spec.red_zone_size == 0
        assert spec.shadow_space_size == 0

    def test_x86_32_callee_saved_regs(self):
        """Test x86_32 callee-saved registers."""
        spec = ABI_SPECS["x86_32_linux"]

        expected_saved = ["ebx", "esi", "edi", "ebp"]

        for reg in expected_saved:
            assert reg in spec.callee_saved_regs, f"Missing callee-saved: {reg}"

    def test_x86_32_windows_abi_spec(self):
        """Test x86_32 Windows ABI spec exists."""
        assert "x86_32_windows" in ABI_SPECS

        spec = ABI_SPECS["x86_32_windows"]

        assert spec.abi_type == ABIType.X86_32_WINDOWS


class TestInitNopEquivalents:
    """Tests for NOP equivalents initialization."""

    def test_init_shuffles_equivalents(self):
        """Test that initialization shuffles equivalents."""
        random.seed(42)
        p1 = NopInsertionPass(config={"seed": 42})

        random.seed(42)
        p2 = NopInsertionPass(config={"seed": 42})

        for arch in p1.NOP_EQUIVALENTS:
            assert arch in p2.NOP_EQUIVALENTS

    def test_nop_equivalents_keys_match_base(self):
        """Test that NOP_EQUIVALENTS keys match NOP_EQUIVALENTS_BASE."""
        p = NopInsertionPass()

        assert set(p.NOP_EQUIVALENTS.keys()) == set(p.NOP_EQUIVALENTS_BASE.keys())

    def test_architectures_in_support_declaration(self):
        """Test that architectures match support declaration."""
        p = NopInsertionPass()

        support = p.get_support()

        assert "x86_64" in support.architectures
        assert "arm64" in support.architectures
        assert "arm32" in support.architectures
        assert "x86" in support.architectures


class TestX8632FunctionHandling:
    """Tests for x86_32 function handling."""

    def test_is_safe_self_redundancy_x86_32(self):
        """Test safe self-redundancy for x86_32."""
        p = NopInsertionPass()

        assert p._is_safe_self_redundancy("eax", 32) is True
        assert p._is_safe_self_redundancy("ecx", 32) is True
        assert p._is_safe_self_redundancy("edx", 32) is True

        assert p._is_safe_self_redundancy("ebx", 32) is False
        assert p._is_safe_self_redundancy("esi", 32) is False
        assert p._is_safe_self_redundancy("edi", 32) is False

    def test_is_safe_self_redundancy_x86_64(self):
        """Test safe self-redundancy for x86_64."""
        p = NopInsertionPass()

        assert p._is_safe_self_redundancy("rax", 64) is True
        assert p._is_safe_self_redundancy("rcx", 64) is True
        assert p._is_safe_self_redundancy("rdx", 64) is True
        assert p._is_safe_self_redundancy("rsi", 64) is True
        assert p._is_safe_self_redundancy("rdi", 64) is True

        assert p._is_safe_self_redundancy("rbx", 64) is False
        assert p._is_safe_self_redundancy("r12", 64) is False
        assert p._is_safe_self_redundancy("r13", 64) is False


class TestArm64RegisterSubstitution:
    """Tests for ARM64 register substitution support."""

    def test_arm64_register_classes_exist(self):
        """Test ARM64 register classes are defined."""
        p = RegisterSubstitutionPass()

        assert "arm64" in p.REGISTER_CLASSES
        assert "gp64" in p.REGISTER_CLASSES["arm64"]
        assert "gp32" in p.REGISTER_CLASSES["arm64"]
        assert "caller_saved" in p.REGISTER_CLASSES["arm64"]
        assert "callee_saved" in p.REGISTER_CLASSES["arm64"]

    def test_arm64_general_purpose_64bit_registers(self):
        """Test ARM64 64-bit general purpose registers."""
        p = RegisterSubstitutionPass()

        gp64 = p.REGISTER_CLASSES["arm64"]["gp64"]

        assert "x0" in gp64
        assert "x1" in gp64
        assert "x7" in gp64
        assert "x17" in gp64
        assert "x28" in gp64

    def test_arm64_general_purpose_32bit_registers(self):
        """Test ARM64 32-bit general purpose registers."""
        p = RegisterSubstitutionPass()

        gp32 = p.REGISTER_CLASSES["arm64"]["gp32"]

        assert "w0" in gp32
        assert "w1" in gp32
        assert "w7" in gp32
        assert "w28" in gp32

    def test_arm64_caller_saved_registers(self):
        """Test ARM64 caller-saved registers."""
        p = RegisterSubstitutionPass()

        caller_saved = p.REGISTER_CLASSES["arm64"]["caller_saved"]

        assert "x0" in caller_saved
        assert "x1" in caller_saved
        assert "x7" in caller_saved
        assert "x17" in caller_saved
        assert "x30" in caller_saved

        assert "x19" not in caller_saved
        assert "x20" not in caller_saved
        assert "x28" not in caller_saved

    def test_arm64_callee_saved_registers(self):
        """Test ARM64 callee-saved registers."""
        p = RegisterSubstitutionPass()

        callee_saved = p.REGISTER_CLASSES["arm64"]["callee_saved"]

        assert "x19" in callee_saved
        assert "x20" in callee_saved
        assert "x28" in callee_saved

        assert "x0" not in callee_saved
        assert "x1" not in callee_saved
        assert "x30" not in callee_saved

    def test_get_register_class_arm64(self):
        """Test getting register class for ARM64."""
        p = RegisterSubstitutionPass()

        reg_class = p._get_register_class("arm64")

        assert "gp64" in reg_class
        assert "caller_saved" in reg_class
        assert "callee_saved" in reg_class

    def test_register_substitution_supports_arm64(self):
        """Test RegisterSubstitutionPass supports ARM64."""
        p = RegisterSubstitutionPass()

        support = p.get_support()

        assert "arm64" in support.architectures


class TestArm64InstructionSubstitution:
    """Tests for ARM64 instruction substitution support."""

    def test_arm64_equivalence_rules_loaded(self):
        """Test ARM64 equivalence rules are loaded."""
        from r2morph.mutations.equivalences import load_equivalence_rules

        rules = load_equivalence_rules("arm64")

        assert len(rules) > 0

    def test_arm64_zero_register_equivalences(self):
        """Test ARM64 zero register equivalences exist."""
        from r2morph.mutations.equivalences import load_equivalence_rules

        rules = load_equivalence_rules("arm64")

        zero_groups = [g for g in rules if any("mov x0, #0" in p or "mov x1, #0" in p for p in g)]
        assert len(zero_groups) > 0

    def test_arm64_nop_equivalences_exist(self):
        """Test ARM64 NOP equivalences exist."""
        from r2morph.mutations.equivalences import load_equivalence_rules

        rules = load_equivalence_rules("arm64")

        nop_groups = [g for g in rules if any("nop" in p.lower() for p in g)]
        assert len(nop_groups) > 0

    def test_instruction_substitution_supports_arm64(self):
        """Test InstructionSubstitutionPass supports ARM64."""
        p = InstructionSubstitutionPass()

        support = p.get_support()

        assert "arm64" in support.architectures

    def test_arm64_in_equivalence_groups(self):
        """Test ARM64 is in equivalence groups."""
        p = InstructionSubstitutionPass()

        assert "arm64" in p.equivalence_groups

    def test_arm64_pattern_to_group_built(self):
        """Test ARM64 pattern to group lookup is built."""
        p = InstructionSubstitutionPass()

        assert "arm64" in p.pattern_to_group


class TestArm64ABISpec:
    """Tests for ARM64 ABI specification."""

    def test_arm64_abi_spec_exists(self):
        """Test ARM64 ABI spec exists."""
        assert "arm64_aapcs" in ABI_SPECS

        spec = ABI_SPECS["arm64_aapcs"]

        from r2morph.analysis.abi_checker import ABIType

        assert spec.abi_type == ABIType.ARM64_AAPCS

    def test_arm64_callee_saved_regs(self):
        """Test ARM64 callee-saved registers."""
        spec = ABI_SPECS["arm64_aapcs"]

        expected_saved = ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"]

        for reg in expected_saved:
            assert reg in spec.callee_saved_regs, f"Missing callee-saved: {reg}"

    def test_arm64_param_regs(self):
        """Test ARM64 parameter registers."""
        spec = ABI_SPECS["arm64_aapcs"]

        expected_params = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]

        for reg in expected_params:
            assert reg in spec.param_regs, f"Missing param register: {reg}"

    def test_arm64_stack_alignment(self):
        """Test ARM64 stack alignment."""
        spec = ABI_SPECS["arm64_aapcs"]

        assert spec.stack_alignment == 16
