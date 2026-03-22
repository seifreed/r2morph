"""
Tests for short jump patching functionality.
"""

from r2morph.mutations.short_jump_patching import (
    ShortJumpPatchingPass,
    RIPRelativeValidationPass,
    detect_rip_relative_displacement,
    validate_instructions_for_rip_relative,
    SHORT_JUMP_EXCLUSIVE,
)
from r2morph.mutations.block_reordering import patch_short_jump_exclusive


class TestShortJumpExclusive:
    """Test short jump exclusive instruction detection."""

    def test_loop_in_list(self):
        assert "loop" in SHORT_JUMP_EXCLUSIVE

    def test_loopne_in_list(self):
        assert "loopne" in SHORT_JUMP_EXCLUSIVE

    def test_loopnz_in_list(self):
        assert "loopnz" in SHORT_JUMP_EXCLUSIVE

    def test_loope_in_list(self):
        assert "loope" in SHORT_JUMP_EXCLUSIVE

    def test_loopz_in_list(self):
        assert "loopz" in SHORT_JUMP_EXCLUSIVE

    def test_jcxz_in_list(self):
        assert "jcxz" in SHORT_JUMP_EXCLUSIVE

    def test_jecxz_in_list(self):
        assert "jecxz" in SHORT_JUMP_EXCLUSIVE

    def test_jrcxz_in_list(self):
        assert "jrcxz" in SHORT_JUMP_EXCLUSIVE

    def test_jmp_not_in_list(self):
        assert "jmp" not in SHORT_JUMP_EXCLUSIVE

    def test_jz_not_in_list(self):
        assert "jz" not in SHORT_JUMP_EXCLUSIVE


class TestPatchShortJumpExclusive:
    """Test patch_short_jump_exclusive function."""

    def test_patch_loop(self):
        result = patch_short_jump_exclusive("loop")
        assert result == "dec rcx\njnz"

    def test_patch_loopne(self):
        result = patch_short_jump_exclusive("loopne")
        assert result == "dec rcx\njnz"

    def test_patch_loopnz(self):
        result = patch_short_jump_exclusive("loopnz")
        assert result == "dec rcx\njnz"

    def test_patch_loope(self):
        result = patch_short_jump_exclusive("loope")
        assert result == "dec rcx\njz"

    def test_patch_loopz(self):
        result = patch_short_jump_exclusive("loopz")
        assert result == "dec rcx\njz"

    def test_patch_jcxz(self):
        result = patch_short_jump_exclusive("jcxz")
        assert result == "test cx, cx\njz"

    def test_patch_jecxz(self):
        result = patch_short_jump_exclusive("jecxz")
        assert result == "test ecx, ecx\njz"

    def test_patch_jrcxz(self):
        result = patch_short_jump_exclusive("jrcxz")
        assert result == "test rcx, rcx\njz"

    def test_patch_jmp_returns_none(self):
        result = patch_short_jump_exclusive("jmp")
        assert result is None

    def test_patch_jz_returns_none(self):
        result = patch_short_jump_exclusive("jz")
        assert result is None

    def test_patch_case_insensitive(self):
        result = patch_short_jump_exclusive("LOOP")
        assert result == "dec rcx\njnz"

    def test_patch_mixed_case(self):
        result = patch_short_jump_exclusive("Jrcxz")
        assert result == "test rcx, rcx\njz"


class TestDetectRipRelativeDisplacement:
    """Test RIP-relative displacement detection."""

    def test_detect_rip_in_disasm(self):
        insn = {"disasm": "mov rax, [rip + 0x1000]"}
        assert detect_rip_relative_displacement(insn) is True

    def test_detect_rip_in_opstr(self):
        insn = {"opstr": "lea rax, [rip + 0x1000]"}
        assert detect_rip_relative_displacement(insn) is True

    def test_no_rip_in_disasm(self):
        insn = {"disasm": "mov rax, [rbx + 0x10]"}
        assert detect_rip_relative_displacement(insn) is False

    def test_no_rip_in_opstr(self):
        insn = {"opstr": "mov rax, rbx"}
        assert detect_rip_relative_displacement(insn) is False

    def test_detect_via_type_lea(self):
        insn = {"type": "lea", "disasm": "lea rax, [rip]"}
        assert detect_rip_relative_displacement(insn) is True

    def test_detect_via_type_mov(self):
        insn = {"type": "mov", "disasm": "mov rax, [rip + 0x100]"}
        assert detect_rip_relative_displacement(insn) is True

    def test_empty_instruction(self):
        insn = {}
        assert detect_rip_relative_displacement(insn) is False

    def test_rip_in_esil(self):
        insn = {"esil": "rip,0x1000,+,[8],rax,="}
        assert detect_rip_relative_displacement(insn) is True


class TestValidateInstructionsForRipRelative:
    """Test instruction validation for RIP-relative."""

    def test_empty_instructions(self):
        result = validate_instructions_for_rip_relative([])
        assert result == []

    def test_no_rip_relative(self):
        instructions = [
            {"addr": 0x1000, "disasm": "mov rax, rbx", "mnemonic": "mov"},
            {"addr": 0x1003, "disasm": "add rax, 10", "mnemonic": "add"},
        ]
        result = validate_instructions_for_rip_relative(instructions)
        assert result == []

    def test_single_rip_relative(self):
        instructions = [
            {"addr": 0x1000, "disasm": "mov rax, [rip + 0x100]", "mnemonic": "mov"},
        ]
        result = validate_instructions_for_rip_relative(instructions)
        assert len(result) == 1
        assert result[0]["address"] == 0x1000
        assert result[0]["reason"] == "RIP-relative addressing detected"

    def test_multiple_rip_relative(self):
        instructions = [
            {"addr": 0x1000, "disasm": "lea rax, [rip + 0x100]", "mnemonic": "lea"},
            {"addr": 0x1005, "disasm": "mov rbx, [rip + 0x200]", "mnemonic": "mov"},
            {"addr": 0x100A, "disasm": "add rax, rbx", "mnemonic": "add"},
        ]
        result = validate_instructions_for_rip_relative(instructions)
        assert len(result) == 2


class TestShortJumpPatchingPass:
    """Test ShortJumpPatchingPass class."""

    def test_init_default_config(self):
        patcher = ShortJumpPatchingPass()
        assert patcher.name == "ShortJumpPatching"
        assert patcher.patch_probability == 1.0

    def test_init_custom_config(self):
        patcher = ShortJumpPatchingPass(config={"probability": 0.5})
        assert patcher.patch_probability == 0.5

    def test_get_replacement_loop(self):
        patcher = ShortJumpPatchingPass()
        result = patcher._get_replacement("loop")
        assert result == ("dec rcx", "jnz")

    def test_get_replacement_jrcxz(self):
        patcher = ShortJumpPatchingPass()
        result = patcher._get_replacement("jrcxz")
        assert result == ("test rcx, rcx", "jz")

    def test_get_replacement_invalid(self):
        patcher = ShortJumpPatchingPass()
        result = patcher._get_replacement("jmp")
        assert result is None


class TestRIPRelativeValidationPass:
    """Test RIPRelativeValidationPass class."""

    def test_init_default_config(self):
        validator = RIPRelativeValidationPass()
        assert validator.name == "RIPRelativeValidation"
        assert validator.fail_on_detect is True

    def test_init_custom_config(self):
        validator = RIPRelativeValidationPass(config={"fail_on_detect": False})
        assert validator.fail_on_detect is False
