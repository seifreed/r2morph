"""
Tests for ARM32, x86_32, and ARM64 architecture support.

Tests for architecture support:
- ARM32 NOP equivalents
- x86_32 NOP equivalents
- ARM64 NOP equivalents
- Caller-saved registers
- Architecture detection
"""

import importlib

from r2morph.analysis.abi_checker import ABI_SPECS, ABIType
from r2morph.core.support import (
    PRODUCT_SUPPORT,
    _normalize_architecture_name,
    classify_target_support,
)
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.mutations.register_substitution_helpers import REGISTER_CLASSES
from tests.utils.assertions import expect

_EXPECTED_SPEC_STACK_ALIGNMENT_16 = 16
_EXPECTED_SPEC_STACK_ALIGNMENT_4 = 4
_EXPECTED_SPEC_STACK_ALIGNMENT_8 = 8


class TestArchitectureSupport:
    """Tests for architecture support matrix."""

    def test_x86_32_in_experimental(self):
        """Test x86_32 is in prolonged experimental architectures."""
        expect(not ("x86" not in PRODUCT_SUPPORT.prolonged_experimental_architectures))

    def test_arm32_in_experimental(self):
        """Test ARM32 is in prolonged experimental architectures."""
        expect(not ("arm32" not in PRODUCT_SUPPORT.prolonged_experimental_architectures))

    def test_arm64_in_experimental(self):
        """Test ARM64 is in prolonged experimental architectures."""
        expect(not ("arm64" not in PRODUCT_SUPPORT.prolonged_experimental_architectures))

    def test_classify_x86_32_target(self):
        """Test x86_32 target classification."""
        result = classify_target_support("ELF", "x86", 32)

        expect(result["tier"] == "prolonged-experimental")
        expect(result["architecture"] == "x86")

    def test_classify_arm32_target(self):
        """Test ARM32 target classification."""
        result = classify_target_support("ELF", "arm", 32)

        expect(result["tier"] == "unsupported")
        expect(not ("architecture" not in result))

    def test_classify_arm64_target(self):
        """Test ARM64 target classification."""
        result = classify_target_support("ELF", "arm64", 64)

        expect(result["tier"] == "prolonged-experimental")
        expect(result["architecture"] == "arm64")

    def test_normalize_x86_32(self):
        """Test x86_32 architecture normalization."""
        expect(_normalize_architecture_name("x86", 32) == "x86")
        # i386 and i686 are normalized to x86
        expect(_normalize_architecture_name("i386", 32) == "x86")
        expect(_normalize_architecture_name("i686", 32) == "x86")

    def test_normalize_x86_64(self):
        """Test x86_64 architecture normalization."""
        expect(_normalize_architecture_name("x86_64", 64) == "x86_64")
        expect(_normalize_architecture_name("amd64", 64) == "x86_64")


class TestNopInsertionArchitecture:
    """Tests for NOP insertion architecture support."""

    def test_x86_32_nop_equivalents_exist(self):
        """Test x86_32 NOP equivalents are defined."""
        config = {"seed": 42}
        p = NopInsertionPass(config=config)

        expect(not ("x86" not in p.NOP_EQUIVALENTS_BASE))
        expect(not (len(p.NOP_EQUIVALENTS_BASE["x86"]) <= 0))

    def test_x86_nop_equivalents_include_64bit(self):
        """Test x86 NOP equivalents include 64-bit variants."""
        config = {"seed": 42}
        p = NopInsertionPass(config=config)

        # After refactoring, x86 and x86_64 equivalents are merged under "x86"
        x86_nops = p.NOP_EQUIVALENTS_BASE["x86"]
        expect(any("rax" in nop for nop in x86_nops))

    def test_x86_32_caller_saved_registers(self):
        """Test x86_32 caller-saved registers."""
        p = NopInsertionPass()

        expect(not ("eax" not in p.CALLER_SAVED_32BIT))
        expect(not ("ecx" not in p.CALLER_SAVED_32BIT))
        expect(not ("edx" not in p.CALLER_SAVED_32BIT))
        expect("ebx" not in p.CALLER_SAVED_32BIT)
        expect("esi" not in p.CALLER_SAVED_32BIT)

    def test_caller_saved_64bit_registers(self):
        """Test x86_64 caller-saved registers."""
        p = NopInsertionPass()

        expect(not ("rax" not in p.CALLER_SAVED_64BIT))
        expect(not ("rcx" not in p.CALLER_SAVED_64BIT))
        expect(not ("rdx" not in p.CALLER_SAVED_64BIT))
        expect("rbx" not in p.CALLER_SAVED_64BIT)


class TestX86NopEquivalentsContent:
    """Tests for x86 NOP equivalents content details."""

    def test_x86_mov_self_32bit_is_nop(self):
        """Test that 32-bit mov self instructions are NOP equivalents."""
        p = NopInsertionPass()

        x86_nops = p.NOP_EQUIVALENTS_BASE["x86"]

        expect(not ("mov eax, eax" not in x86_nops))
        expect(not ("mov ebx, ebx" not in x86_nops))

    def test_x86_xchg_self_is_nop(self):
        """Test self-exchange operations are NOP equivalents."""
        p = NopInsertionPass()

        x86_nops = p.NOP_EQUIVALENTS_BASE["x86"]

        expect(not ("xchg eax, eax" not in x86_nops))
        expect(not ("xchg rax, rax" not in x86_nops))

    def test_x86_registers_32bit_complete(self):
        """Test x86 32-bit register list is complete."""
        p = NopInsertionPass()

        expected_regs = ["eax", "ebx", "ecx", "edx", "esi", "edi"]

        for reg in expected_regs:
            expect(not (reg not in p.REGISTERS_32BIT), f"Missing 32-bit register: {reg}")


class TestX8632NopEquivalents:
    """Tests for x86_32 NOP equivalents content."""

    def test_x86_32_xchg_self_is_nop(self):
        """Test that xchg eax, eax is a NOP equivalent."""
        p = NopInsertionPass()

        x86_nops = p.NOP_EQUIVALENTS_BASE["x86"]

        expect(not ("xchg eax, eax" not in x86_nops))
        expect(not ("xchg ebx, ebx" not in x86_nops))
        expect(not ("xchg ecx, ecx" not in x86_nops))
        expect(not ("xchg edx, edx" not in x86_nops))

    def test_x86_32_mov_self_is_nop(self):
        """Test that mov eax, eax is a NOP equivalent."""
        p = NopInsertionPass()

        x86_nops = p.NOP_EQUIVALENTS_BASE["x86"]

        expect(not ("mov eax, eax" not in x86_nops))
        expect(not ("mov ebx, ebx" not in x86_nops))
        expect(not ("mov ecx, ecx" not in x86_nops))
        expect(not ("mov edx, edx" not in x86_nops))

    def test_x86_32_lea_self_is_nop(self):
        """Test that lea eax, [eax] is a NOP equivalent."""
        p = NopInsertionPass()

        x86_nops = p.NOP_EQUIVALENTS_BASE["x86"]

        expect(not ("lea eax, [eax]" not in x86_nops))
        expect(not ("lea ebx, [ebx]" not in x86_nops))
        expect(not ("lea ecx, [ecx]" not in x86_nops))
        expect(not ("lea edx, [edx]" not in x86_nops))

    def test_x86_32_registers_complete(self):
        """Test x86_32 register list is complete."""
        p = NopInsertionPass()

        expected_regs = ["eax", "ebx", "ecx", "edx", "esi", "edi"]

        for reg in expected_regs:
            expect(not (reg not in p.REGISTERS_32BIT), f"Missing x86_32 register: {reg}")


class TestABISpecsArm32X8632:
    """Tests for ABI specs for ARM32 and x86_32."""

    def test_arm32_abi_spec_exists(self):
        """Test ARM32 ABI spec exists."""
        expect(not ("arm32_aapcs" not in ABI_SPECS))

        spec = ABI_SPECS["arm32_aapcs"]

        expect(spec.abi_type == ABIType.ARM32_AAPCS)
        expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_8)
        expect(spec.red_zone_size == 0)
        expect(spec.shadow_space_size == 0)

    def test_arm32_callee_saved_regs(self):
        """Test ARM32 callee-saved registers."""
        spec = ABI_SPECS["arm32_aapcs"]

        expected_saved = ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"]

        for reg in expected_saved:
            expect(not (reg not in spec.callee_saved_regs), f"Missing callee-saved: {reg}")

    def test_arm32_param_regs(self):
        """Test ARM32 parameter registers."""
        spec = ABI_SPECS["arm32_aapcs"]

        expected_params = ["r0", "r1", "r2", "r3"]

        for reg in expected_params:
            expect(not (reg not in spec.param_regs), f"Missing param register: {reg}")

    def test_x86_32_linux_abi_spec_exists(self):
        """Test x86_32 Linux ABI spec exists."""
        expect(not ("x86_32_linux" not in ABI_SPECS))

        spec = ABI_SPECS["x86_32_linux"]

        expect(spec.abi_type == ABIType.X86_32_LINUX)
        expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_4)
        expect(spec.red_zone_size == 0)
        expect(spec.shadow_space_size == 0)

    def test_x86_32_callee_saved_regs(self):
        """Test x86_32 callee-saved registers."""
        spec = ABI_SPECS["x86_32_linux"]

        expected_saved = ["ebx", "esi", "edi", "ebp"]

        for reg in expected_saved:
            expect(not (reg not in spec.callee_saved_regs), f"Missing callee-saved: {reg}")

    def test_x86_32_windows_abi_spec(self):
        """Test x86_32 Windows ABI spec exists."""
        expect(not ("x86_32_windows" not in ABI_SPECS))

        spec = ABI_SPECS["x86_32_windows"]

        expect(spec.abi_type == ABIType.X86_32_WINDOWS)


class TestInitNopEquivalents:
    """Tests for NOP equivalents initialization."""

    def test_init_shuffles_equivalents(self):
        """Test that initialization shuffles equivalents."""
        p = NopInsertionPass(config={"seed": 42})
        p._init_nop_equivalents()

        expect(not ("x86" not in p.NOP_EQUIVALENTS))

    def test_nop_equivalents_keys_match_base(self):
        """Test that NOP_EQUIVALENTS keys match NOP_EQUIVALENTS_BASE."""
        p = NopInsertionPass()
        p._init_nop_equivalents()

        expect(set(p.NOP_EQUIVALENTS.keys()) == set(p.NOP_EQUIVALENTS_BASE.keys()))

    def test_architectures_in_support_declaration(self):
        """Test that x86_64 architecture is supported."""
        p = NopInsertionPass()

        support = p.get_support()

        expect(not ("x86_64" not in support.architectures))


class TestX8632FunctionHandling:
    """Tests for x86_32 function handling."""

    def test_is_safe_self_redundancy_x86_32(self):
        """Test safe self-redundancy for x86_32."""
        p = NopInsertionPass()

        expect(not (p._is_safe_self_redundancy("eax", 32) is not True))
        expect(not (p._is_safe_self_redundancy("ecx", 32) is not True))
        expect(not (p._is_safe_self_redundancy("edx", 32) is not True))

        expect(not (p._is_safe_self_redundancy("ebx", 32) is not False))
        expect(not (p._is_safe_self_redundancy("esi", 32) is not False))
        expect(not (p._is_safe_self_redundancy("edi", 32) is not False))

    def test_is_safe_self_redundancy_x86_64(self):
        """Test safe self-redundancy for x86_64."""
        p = NopInsertionPass()

        expect(not (p._is_safe_self_redundancy("rax", 64) is not True))
        expect(not (p._is_safe_self_redundancy("rcx", 64) is not True))
        expect(not (p._is_safe_self_redundancy("rdx", 64) is not True))
        expect(not (p._is_safe_self_redundancy("rsi", 64) is not True))
        expect(not (p._is_safe_self_redundancy("rdi", 64) is not True))

        expect(not (p._is_safe_self_redundancy("rbx", 64) is not False))
        expect(not (p._is_safe_self_redundancy("r12", 64) is not False))
        expect(not (p._is_safe_self_redundancy("r13", 64) is not False))


class TestArm64RegisterSubstitution:
    """Tests for ARM64 register substitution support."""

    def test_arm64_register_classes_exist(self):
        """Test ARM64 register classes are defined."""
        expect(not ("arm64" not in REGISTER_CLASSES))
        expect(not ("gp64" not in REGISTER_CLASSES["arm64"]))
        expect(not ("gp32" not in REGISTER_CLASSES["arm64"]))
        expect(not ("caller_saved" not in REGISTER_CLASSES["arm64"]))
        expect(not ("callee_saved" not in REGISTER_CLASSES["arm64"]))

    def test_arm64_general_purpose_64bit_registers(self):
        """Test ARM64 64-bit general purpose registers."""
        gp64 = REGISTER_CLASSES["arm64"]["gp64"]

        expect(not ("x0" not in gp64))
        expect(not ("x1" not in gp64))
        expect(not ("x7" not in gp64))
        expect(not ("x17" not in gp64))
        expect(not ("x28" not in gp64))

    def test_arm64_general_purpose_32bit_registers(self):
        """Test ARM64 32-bit general purpose registers."""
        gp32 = REGISTER_CLASSES["arm64"]["gp32"]

        expect(not ("w0" not in gp32))
        expect(not ("w1" not in gp32))
        expect(not ("w7" not in gp32))
        expect(not ("w28" not in gp32))

    def test_arm64_caller_saved_registers(self):
        """Test ARM64 caller-saved registers."""
        caller_saved = REGISTER_CLASSES["arm64"]["caller_saved"]

        expect(not ("x0" not in caller_saved))
        expect(not ("x1" not in caller_saved))
        expect(not ("x7" not in caller_saved))
        expect(not ("x17" not in caller_saved))
        expect(not ("x30" not in caller_saved))

        expect("x19" not in caller_saved)
        expect("x20" not in caller_saved)
        expect("x28" not in caller_saved)

    def test_arm64_callee_saved_registers(self):
        """Test ARM64 callee-saved registers."""
        callee_saved = REGISTER_CLASSES["arm64"]["callee_saved"]

        expect(not ("x19" not in callee_saved))
        expect(not ("x20" not in callee_saved))
        expect(not ("x28" not in callee_saved))

        expect("x0" not in callee_saved)
        expect("x1" not in callee_saved)
        expect("x30" not in callee_saved)

    def test_get_register_class_arm64(self):
        """Test getting register class for ARM64."""
        p = RegisterSubstitutionPass()

        reg_class = p._get_register_class("arm64")

        expect(not ("gp64" not in reg_class))
        expect(not ("caller_saved" not in reg_class))
        expect(not ("callee_saved" not in reg_class))

    def test_register_substitution_supports_arm64(self):
        """Test RegisterSubstitutionPass supports ARM64."""
        p = RegisterSubstitutionPass()

        support = p.get_support()

        expect(not ("arm64" not in support.architectures))


class TestArm64InstructionSubstitution:
    """Tests for ARM64 instruction substitution support."""

    def test_arm64_equivalence_rules_loaded(self):
        """Test ARM64 equivalence rules are loaded."""
        load_equivalence_rules = importlib.import_module("r2morph.mutations.equivalences").load_equivalence_rules

        rules = load_equivalence_rules("arm64")

        expect(not (len(rules) <= 0))

    def test_arm64_zero_register_equivalences(self):
        """Test ARM64 zero register equivalences exist."""
        load_equivalence_rules = importlib.import_module("r2morph.mutations.equivalences").load_equivalence_rules

        rules = load_equivalence_rules("arm64")

        zero_groups = [g for g in rules if any("mov x0, #0" in p or "mov x1, #0" in p for p in g)]
        expect(not (len(zero_groups) <= 0))

    def test_arm64_nop_equivalences_exist(self):
        """Test ARM64 NOP equivalences exist."""
        load_equivalence_rules = importlib.import_module("r2morph.mutations.equivalences").load_equivalence_rules

        rules = load_equivalence_rules("arm64")

        nop_groups = [g for g in rules if any("nop" in p.lower() for p in g)]
        expect(not (len(nop_groups) <= 0))

    def test_instruction_substitution_supports_x86_64(self):
        """Test InstructionSubstitutionPass supports x86_64."""
        p = InstructionSubstitutionPass()

        support = p.get_support()

        expect(not ("x86_64" not in support.architectures))

    def test_x86_in_equivalence_groups(self):
        """Test x86 is in equivalence groups."""
        p = InstructionSubstitutionPass()

        expect(not ("x86" not in p.equivalence_groups))

    def test_x86_pattern_to_group_built(self):
        """Test x86 pattern to group lookup is built."""
        p = InstructionSubstitutionPass()

        expect(not ("x86" not in p.pattern_to_group))


class TestArm64ABISpec:
    """Tests for ARM64 ABI specification."""

    def test_arm64_abi_spec_exists(self):
        """Test ARM64 ABI spec exists."""
        expect(not ("arm64_aapcs" not in ABI_SPECS))

        spec = ABI_SPECS["arm64_aapcs"]

        a_b_i_type = importlib.import_module("r2morph.analysis.abi_checker").ABIType

        expect(spec.abi_type == a_b_i_type.ARM64_AAPCS)

    def test_arm64_callee_saved_regs(self):
        """Test ARM64 callee-saved registers."""
        spec = ABI_SPECS["arm64_aapcs"]

        expected_saved = ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"]

        for reg in expected_saved:
            expect(not (reg not in spec.callee_saved_regs), f"Missing callee-saved: {reg}")

    def test_arm64_param_regs(self):
        """Test ARM64 parameter registers."""
        spec = ABI_SPECS["arm64_aapcs"]

        expected_params = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]

        for reg in expected_params:
            expect(not (reg not in spec.param_regs), f"Missing param register: {reg}")

    def test_arm64_stack_alignment(self):
        """Test ARM64 stack alignment."""
        spec = ABI_SPECS["arm64_aapcs"]

        expect(spec.stack_alignment == _EXPECTED_SPEC_STACK_ALIGNMENT_16)
