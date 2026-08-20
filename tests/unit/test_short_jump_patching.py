"""
Tests for short jump patching functionality.
"""

from r2morph.mutations.short_jump_patching import (
    SHORT_JUMP_EXCLUSIVE,
    RIPRelativeValidationPass,
    ShortJumpPatchingPass,
    detect_rip_relative_displacement,
    validate_instructions_for_rip_relative,
)
from tests.utils.assertions import expect

_EXPECTED_LEN_RESULT_2 = 2
_EXPECTED_PATCHER_PATCH_PROBABILITY_0_5 = 0.5
_EXPECTED_RESULT_0_ADDRESS_4096 = 0x1000


def patch_short_jump_exclusive(mnemonic: str) -> str | None:
    """Return replacement instruction pair as a string, or None."""
    key = mnemonic.lower()
    entry = SHORT_JUMP_EXCLUSIVE.get(key)
    if entry is None:
        return None
    return f"{entry[0]}\n{entry[1]}"


class TestShortJumpExclusive:
    """Test short jump exclusive instruction detection."""

    def test_loop_in_list(self):
        expect(not ("loop" not in SHORT_JUMP_EXCLUSIVE))

    def test_loopne_in_list(self):
        expect(not ("loopne" not in SHORT_JUMP_EXCLUSIVE))

    def test_loopnz_in_list(self):
        expect(not ("loopnz" not in SHORT_JUMP_EXCLUSIVE))

    def test_loope_in_list(self):
        expect(not ("loope" not in SHORT_JUMP_EXCLUSIVE))

    def test_loopz_in_list(self):
        expect(not ("loopz" not in SHORT_JUMP_EXCLUSIVE))

    def test_jcxz_in_list(self):
        expect(not ("jcxz" not in SHORT_JUMP_EXCLUSIVE))

    def test_jecxz_in_list(self):
        expect(not ("jecxz" not in SHORT_JUMP_EXCLUSIVE))

    def test_jrcxz_in_list(self):
        expect(not ("jrcxz" not in SHORT_JUMP_EXCLUSIVE))

    def test_jmp_not_in_list(self):
        expect("jmp" not in SHORT_JUMP_EXCLUSIVE)

    def test_jz_not_in_list(self):
        expect("jz" not in SHORT_JUMP_EXCLUSIVE)


class TestPatchShortJumpExclusive:
    """Test patch_short_jump_exclusive function."""

    def test_patch_loop(self):
        result = patch_short_jump_exclusive("loop")
        expect(result == "dec rcx\njnz")

    def test_patch_loopne(self):
        result = patch_short_jump_exclusive("loopne")
        expect(result == "dec rcx\njnz")

    def test_patch_loopnz(self):
        result = patch_short_jump_exclusive("loopnz")
        expect(result == "dec rcx\njnz")

    def test_patch_loope(self):
        result = patch_short_jump_exclusive("loope")
        expect(result == "dec rcx\njz")

    def test_patch_loopz(self):
        result = patch_short_jump_exclusive("loopz")
        expect(result == "dec rcx\njz")

    def test_patch_jcxz(self):
        result = patch_short_jump_exclusive("jcxz")
        expect(result == "test cx, cx\njz")

    def test_patch_jecxz(self):
        result = patch_short_jump_exclusive("jecxz")
        expect(result == "test ecx, ecx\njz")

    def test_patch_jrcxz(self):
        result = patch_short_jump_exclusive("jrcxz")
        expect(result == "test rcx, rcx\njz")

    def test_patch_jmp_returns_none(self):
        result = patch_short_jump_exclusive("jmp")
        expect(not (result is not None))

    def test_patch_jz_returns_none(self):
        result = patch_short_jump_exclusive("jz")
        expect(not (result is not None))

    def test_patch_case_insensitive(self):
        result = patch_short_jump_exclusive("LOOP")
        expect(result == "dec rcx\njnz")

    def test_patch_mixed_case(self):
        result = patch_short_jump_exclusive("Jrcxz")
        expect(result == "test rcx, rcx\njz")


class TestDetectRipRelativeDisplacement:
    """Test RIP-relative displacement detection."""

    def test_detect_rip_in_disasm(self):
        insn = {"disasm": "mov rax, [rip + 0x1000]"}
        expect(not (detect_rip_relative_displacement(insn) is not True))

    def test_detect_rip_in_opstr(self):
        insn = {"opstr": "lea rax, [rip + 0x1000]"}
        expect(not (detect_rip_relative_displacement(insn) is not True))

    def test_no_rip_in_disasm(self):
        insn = {"disasm": "mov rax, [rbx + 0x10]"}
        expect(not (detect_rip_relative_displacement(insn) is not False))

    def test_no_rip_in_opstr(self):
        insn = {"opstr": "mov rax, rbx"}
        expect(not (detect_rip_relative_displacement(insn) is not False))

    def test_detect_via_type_lea(self):
        insn = {"type": "lea", "disasm": "lea rax, [rip]"}
        expect(not (detect_rip_relative_displacement(insn) is not True))

    def test_detect_via_type_mov(self):
        insn = {"type": "mov", "disasm": "mov rax, [rip + 0x100]"}
        expect(not (detect_rip_relative_displacement(insn) is not True))

    def test_empty_instruction(self):
        insn = {}
        expect(not (detect_rip_relative_displacement(insn) is not False))

    def test_rip_in_esil(self):
        insn = {"esil": "rip,0x1000,+,[8],rax,="}
        expect(not (detect_rip_relative_displacement(insn) is not True))


class TestValidateInstructionsForRipRelative:
    """Test instruction validation for RIP-relative."""

    def test_empty_instructions(self):
        result = validate_instructions_for_rip_relative([])
        expect(result == [])

    def test_no_rip_relative(self):
        instructions = [
            {"addr": 0x1000, "disasm": "mov rax, rbx", "mnemonic": "mov"},
            {"addr": 0x1003, "disasm": "add rax, 10", "mnemonic": "add"},
        ]
        result = validate_instructions_for_rip_relative(instructions)
        expect(result == [])

    def test_single_rip_relative(self):
        instructions = [
            {"addr": 0x1000, "disasm": "mov rax, [rip + 0x100]", "mnemonic": "mov"},
        ]
        result = validate_instructions_for_rip_relative(instructions)
        expect(len(result) == 1)
        expect(result[0]["address"] == _EXPECTED_RESULT_0_ADDRESS_4096)
        expect(result[0]["reason"] == "RIP-relative addressing detected")

    def test_multiple_rip_relative(self):
        instructions = [
            {"addr": 0x1000, "disasm": "lea rax, [rip + 0x100]", "mnemonic": "lea"},
            {"addr": 0x1005, "disasm": "mov rbx, [rip + 0x200]", "mnemonic": "mov"},
            {"addr": 0x100A, "disasm": "add rax, rbx", "mnemonic": "add"},
        ]
        result = validate_instructions_for_rip_relative(instructions)
        expect(len(result) == _EXPECTED_LEN_RESULT_2)


class TestShortJumpPatchingPass:
    """Test ShortJumpPatchingPass class."""

    def test_init_default_config(self):
        patcher = ShortJumpPatchingPass()
        expect(patcher.name == "ShortJumpPatching")
        expect(patcher.patch_probability == 1.0)

    def test_init_custom_config(self):
        patcher = ShortJumpPatchingPass(config={"probability": 0.5})
        expect(patcher.patch_probability == _EXPECTED_PATCHER_PATCH_PROBABILITY_0_5)

    def test_get_replacement_loop(self):
        patcher = ShortJumpPatchingPass()
        result = patcher._get_replacement("loop")
        expect(result == ("dec rcx", "jnz"))

    def test_get_replacement_jrcxz(self):
        patcher = ShortJumpPatchingPass()
        result = patcher._get_replacement("jrcxz")
        expect(result == ("test rcx, rcx", "jz"))

    def test_get_replacement_invalid(self):
        patcher = ShortJumpPatchingPass()
        result = patcher._get_replacement("jmp")
        expect(not (result is not None))


class TestRIPRelativeValidationPass:
    """Test RIPRelativeValidationPass class."""

    def test_init_default_config(self):
        validator = RIPRelativeValidationPass()
        expect(validator.name == "RIPRelativeValidation")
        expect(not (validator.fail_on_detect is not True))

    def test_init_custom_config(self):
        validator = RIPRelativeValidationPass(config={"fail_on_detect": False})
        expect(not (validator.fail_on_detect is not False))
