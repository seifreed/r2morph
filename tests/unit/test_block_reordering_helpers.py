"""
Tests for block reordering helper functions.
"""

import pytest
import random
from r2morph.mutations.block_reordering import (
    shuffle_blocks,
    remove_redundant_fallthrough,
    generate_block_asm,
    patch_short_jump_exclusive,
)


class TestShuffleBlocks:
    """Test shuffle_blocks function."""

    def test_empty_blocks(self):
        result = shuffle_blocks([])
        assert result == []

    def test_single_block(self):
        blocks = [{"addr": 0x1000, "asm": "mov rax, rbx"}]
        result = shuffle_blocks(blocks)
        assert len(result) == 1
        assert result[0]["addr"] == 0x1000

    def test_two_blocks_first_stays(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, rbx"},
            {"addr": 0x1010, "asm": "add rax, 10"},
        ]
        random.seed(42)
        result = shuffle_blocks(blocks)
        assert result[0]["addr"] == 0x1000

    def test_multiple_blocks_first_stays(self):
        blocks = [
            {"addr": 0x1000, "asm": "entry:"},
            {"addr": 0x1010, "asm": "block_a:"},
            {"addr": 0x1020, "asm": "block_b:"},
            {"addr": 0x1030, "asm": "block_c:"},
        ]
        random.seed(42)
        result = shuffle_blocks(blocks)
        assert result[0]["addr"] == 0x1000
        assert len(result) == 4

    def test_first_block_preserved(self):
        """First block should always remain at index 0."""
        blocks = [
            {"addr": 0x1000, "name": "entry"},
            {"addr": 0x1010, "name": "block1"},
            {"addr": 0x1020, "name": "block2"},
            {"addr": 0x1030, "name": "block3"},
        ]
        for _ in range(10):
            result = shuffle_blocks(blocks.copy())
            assert result[0]["addr"] == 0x1000
            assert len(result) == 4


class TestRemoveRedundantFallthrough:
    """Test remove_redundant_fallthrough function."""

    def test_empty_blocks(self):
        result = remove_redundant_fallthrough([])
        assert result == []

    def test_single_block(self):
        blocks = [{"addr": 0x1000, "asm": "mov rax, rbx\nret"}]
        result = remove_redundant_fallthrough(blocks)
        assert len(result) == 1

    def test_no_redundant_jumps(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, rbx\njmp block_0x1020"},
            {"addr": 0x1010, "asm": "add rax, 10"},
            {"addr": 0x1020, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        assert len(result) == 3

    def test_redundant_jmp_removed(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, rbx\njmp block_0x1010"},
            {"addr": 0x1010, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        assert "jmp block_0x1010" not in result[0]["asm"]

    def test_non_redundant_jmp_kept(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, rbx\njmp block_0x1030"},
            {"addr": 0x1010, "asm": "add rax, 10"},
            {"addr": 0x1020, "asm": "sub rax, 5"},
            {"addr": 0x1030, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        assert "jmp block_0x1030" in result[0]["asm"]

    def test_multiple_blocks_sequence(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, 0\njmp block_0x1010"},
            {"addr": 0x1010, "asm": "add rax, 1\njmp block_0x1020"},
            {"addr": 0x1020, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        assert "jmp block_0x1010" not in result[0]["asm"]
        assert "jmp block_0x1020" not in result[1]["asm"]

    def test_block_without_asm(self):
        blocks = [
            {"addr": 0x1000},
            {"addr": 0x1010, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        assert len(result) == 2


class TestGenerateBlockAsm:
    """Test generate_block_asm function."""

    def test_empty_ops(self):
        result = generate_block_asm([], "test_label")
        assert "test_label:" in result

    def test_single_instruction(self):
        ops = [{"mnemonic": "mov", "opcode": "mov rax, rbx", "bytes": "4889C0", "mutated": True}]
        result = generate_block_asm(ops, "start")
        assert "start:" in result
        assert "mov rax, rbx" in result

    def test_instruction_with_bytes(self):
        ops = [{"bytes": "9090", "mutated": False}]
        result = generate_block_asm(ops, "block1")
        assert "block1:" in result
        assert "db" in result

    def test_multiple_instructions(self):
        ops = [
            {"opcode": "push rax", "mutated": True},
            {"opcode": "pop rbx", "mutated": True},
        ]
        result = generate_block_asm(ops, "func")
        assert "func:" in result
        assert "push rax" in result
        assert "pop rbx" in result


class TestPatchShortJumpExclusive:
    """Test patch_short_jump_exclusive function."""

    def test_loop_returns_replacement(self):
        result = patch_short_jump_exclusive("loop")
        assert result == "dec rcx\njnz"

    def test_loopne_returns_replacement(self):
        result = patch_short_jump_exclusive("loopne")
        assert result == "dec rcx\njnz"

    def test_loopnz_returns_replacement(self):
        result = patch_short_jump_exclusive("loopnz")
        assert result == "dec rcx\njnz"

    def test_loope_returns_replacement(self):
        result = patch_short_jump_exclusive("loope")
        assert result == "dec rcx\njz"

    def test_loopz_returns_replacement(self):
        result = patch_short_jump_exclusive("loopz")
        assert result == "dec rcx\njz"

    def test_jcxz_returns_replacement(self):
        result = patch_short_jump_exclusive("jcxz")
        assert result == "test cx, cx\njz"

    def test_jecxz_returns_replacement(self):
        result = patch_short_jump_exclusive("jecxz")
        assert result == "test ecx, ecx\njz"

    def test_jrcxz_returns_replacement(self):
        result = patch_short_jump_exclusive("jrcxz")
        assert result == "test rcx, rcx\njz"

    def test_jmp_returns_none(self):
        result = patch_short_jump_exclusive("jmp")
        assert result is None

    def test_jz_returns_none(self):
        result = patch_short_jump_exclusive("jz")
        assert result is None

    def test_case_insensitive(self):
        result = patch_short_jump_exclusive("LOOP")
        assert result == "dec rcx\njnz"

        result = patch_short_jump_exclusive("jRCXz")
        assert result == "test rcx, rcx\njz"

    def test_empty_returns_none(self):
        result = patch_short_jump_exclusive("")
        assert result is None

    def test_unknown_mnemonic_returns_none(self):
        result = patch_short_jump_exclusive("call")
        assert result is None

        result = patch_short_jump_exclusive("ret")
        assert result is None
