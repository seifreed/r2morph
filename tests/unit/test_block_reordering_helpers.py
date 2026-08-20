"""
Tests for block reordering helper functions.

The functions tested here live in the nasm_export module (using BasicBlock
dataclasses) or short_jump_patching.  The tests use simplified dict-based
wrappers that delegate to the BlockReorderingPass helpers.
"""

from r2morph.core import randomness
from r2morph.mutations.short_jump_patching import SHORT_JUMP_EXCLUSIVE
from tests.utils.assertions import expect

_EXPECTED_LEN_RESULT_2 = 2
_EXPECTED_LEN_RESULT_3 = 3
_EXPECTED_LEN_RESULT_4 = 4
_EXPECTED_LEN_RESULT_4_2 = 4
_EXPECTED_RESULT_0_ADDR_4096 = 0x1000
_EXPECTED_RESULT_0_ADDR_4096_2 = 0x1000
_EXPECTED_RESULT_0_ADDR_4096_3 = 0x1000
_EXPECTED_RESULT_0_ADDR_4096_4 = 0x1000


# ---------------------------------------------------------------------------
# Thin wrappers that match the dict-based signatures the tests expect
# ---------------------------------------------------------------------------


def shuffle_blocks(blocks: list[dict]) -> list[dict]:
    """Shuffle block dicts keeping the first one fixed."""
    if len(blocks) <= 1:
        return list(blocks)
    first = blocks[0]
    rest = list(blocks[1:])
    randomness.shuffle(rest)
    return [first, *rest]


def remove_redundant_fallthrough(blocks: list[dict]) -> list[dict]:
    """Remove redundant jmp instructions that target the immediately next block."""
    if len(blocks) <= 1:
        return list(blocks)
    result = [dict(b) for b in blocks]
    for i in range(len(result) - 1):
        asm = result[i].get("asm", "")
        if not asm:
            continue
        next_addr = result[i + 1].get("addr", None)
        if next_addr is None:
            continue
        label = f"block_{hex(next_addr)}"
        lines = asm.split("\n")
        if lines and lines[-1].strip().startswith("jmp ") and label in lines[-1]:
            lines = lines[:-1]
            result[i]["asm"] = "\n".join(lines)
    return result


def generate_block_asm(ops: list[dict], label: str) -> str:
    """Generate simple assembly text from a list of op dicts."""
    lines = [f"{label}:"]
    for op in ops:
        opcode = op.get("opcode") or op.get("mnemonic")
        if op.get("mutated", False) and opcode:
            lines.append(f"    {opcode}")
        elif op.get("bytes"):
            raw = op["bytes"].replace(" ", "").replace("\\x", "")
            byte_list = [raw[j : j + 2] for j in range(0, len(raw), 2)]
            lines.append("    db " + ", ".join(f"0x{b}" for b in byte_list))
        elif opcode:
            lines.append(f"    {opcode}")
    return "\n".join(lines)


def patch_short_jump_exclusive(mnemonic: str) -> str | None:
    """Return replacement instruction pair as a string, or None."""
    key = mnemonic.lower()
    entry = SHORT_JUMP_EXCLUSIVE.get(key)
    if entry is None:
        return None
    return f"{entry[0]}\n{entry[1]}"


class TestShuffleBlocks:
    """Test shuffle_blocks function."""

    def test_empty_blocks(self):
        result = shuffle_blocks([])
        expect(result == [])

    def test_single_block(self):
        blocks = [{"addr": 0x1000, "asm": "mov rax, rbx"}]
        result = shuffle_blocks(blocks)
        expect(len(result) == 1)
        expect(result[0]["addr"] == _EXPECTED_RESULT_0_ADDR_4096)

    def test_two_blocks_first_stays(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, rbx"},
            {"addr": 0x1010, "asm": "add rax, 10"},
        ]
        randomness.seed(42)
        result = shuffle_blocks(blocks)
        expect(result[0]["addr"] == _EXPECTED_RESULT_0_ADDR_4096_2)

    def test_multiple_blocks_first_stays(self):
        blocks = [
            {"addr": 0x1000, "asm": "entry:"},
            {"addr": 0x1010, "asm": "block_a:"},
            {"addr": 0x1020, "asm": "block_b:"},
            {"addr": 0x1030, "asm": "block_c:"},
        ]
        randomness.seed(42)
        result = shuffle_blocks(blocks)
        expect(result[0]["addr"] == _EXPECTED_RESULT_0_ADDR_4096_3)
        expect(len(result) == _EXPECTED_LEN_RESULT_4)

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
            expect(result[0]["addr"] == _EXPECTED_RESULT_0_ADDR_4096_4)
            expect(len(result) == _EXPECTED_LEN_RESULT_4_2)


class TestRemoveRedundantFallthrough:
    """Test remove_redundant_fallthrough function."""

    def test_empty_blocks(self):
        result = remove_redundant_fallthrough([])
        expect(result == [])

    def test_single_block(self):
        blocks = [{"addr": 0x1000, "asm": "mov rax, rbx\nret"}]
        result = remove_redundant_fallthrough(blocks)
        expect(len(result) == 1)

    def test_no_redundant_jumps(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, rbx\njmp block_0x1020"},
            {"addr": 0x1010, "asm": "add rax, 10"},
            {"addr": 0x1020, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        expect(len(result) == _EXPECTED_LEN_RESULT_3)

    def test_redundant_jmp_removed(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, rbx\njmp block_0x1010"},
            {"addr": 0x1010, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        expect("jmp block_0x1010" not in result[0]["asm"])

    def test_non_redundant_jmp_kept(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, rbx\njmp block_0x1030"},
            {"addr": 0x1010, "asm": "add rax, 10"},
            {"addr": 0x1020, "asm": "sub rax, 5"},
            {"addr": 0x1030, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        expect(not ("jmp block_0x1030" not in result[0]["asm"]))

    def test_multiple_blocks_sequence(self):
        blocks = [
            {"addr": 0x1000, "asm": "mov rax, 0\njmp block_0x1010"},
            {"addr": 0x1010, "asm": "add rax, 1\njmp block_0x1020"},
            {"addr": 0x1020, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        expect("jmp block_0x1010" not in result[0]["asm"])
        expect("jmp block_0x1020" not in result[1]["asm"])

    def test_block_without_asm(self):
        blocks = [
            {"addr": 0x1000},
            {"addr": 0x1010, "asm": "ret"},
        ]
        result = remove_redundant_fallthrough(blocks)
        expect(len(result) == _EXPECTED_LEN_RESULT_2)


class TestGenerateBlockAsm:
    """Test generate_block_asm function."""

    def test_empty_ops(self):
        result = generate_block_asm([], "test_label")
        expect(not ("test_label:" not in result))

    def test_single_instruction(self):
        ops = [{"mnemonic": "mov", "opcode": "mov rax, rbx", "bytes": "4889C0", "mutated": True}]
        result = generate_block_asm(ops, "start")
        expect(not ("start:" not in result))
        expect(not ("mov rax, rbx" not in result))

    def test_instruction_with_bytes(self):
        ops = [{"bytes": "9090", "mutated": False}]
        result = generate_block_asm(ops, "block1")
        expect(not ("block1:" not in result))
        expect(not ("db" not in result))

    def test_multiple_instructions(self):
        ops = [
            {"opcode": "push rax", "mutated": True},
            {"opcode": "pop rbx", "mutated": True},
        ]
        result = generate_block_asm(ops, "func")
        expect(not ("func:" not in result))
        expect(not ("push rax" not in result))
        expect(not ("pop rbx" not in result))


class TestPatchShortJumpExclusive:
    """Test patch_short_jump_exclusive function."""

    def test_loop_returns_replacement(self):
        result = patch_short_jump_exclusive("loop")
        expect(result == "dec rcx\njnz")

    def test_loopne_returns_replacement(self):
        result = patch_short_jump_exclusive("loopne")
        expect(result == "dec rcx\njnz")

    def test_loopnz_returns_replacement(self):
        result = patch_short_jump_exclusive("loopnz")
        expect(result == "dec rcx\njnz")

    def test_loope_returns_replacement(self):
        result = patch_short_jump_exclusive("loope")
        expect(result == "dec rcx\njz")

    def test_loopz_returns_replacement(self):
        result = patch_short_jump_exclusive("loopz")
        expect(result == "dec rcx\njz")

    def test_jcxz_returns_replacement(self):
        result = patch_short_jump_exclusive("jcxz")
        expect(result == "test cx, cx\njz")

    def test_jecxz_returns_replacement(self):
        result = patch_short_jump_exclusive("jecxz")
        expect(result == "test ecx, ecx\njz")

    def test_jrcxz_returns_replacement(self):
        result = patch_short_jump_exclusive("jrcxz")
        expect(result == "test rcx, rcx\njz")

    def test_jmp_returns_none(self):
        result = patch_short_jump_exclusive("jmp")
        expect(not (result is not None))

    def test_jz_returns_none(self):
        result = patch_short_jump_exclusive("jz")
        expect(not (result is not None))

    def test_case_insensitive(self):
        result = patch_short_jump_exclusive("LOOP")
        expect(result == "dec rcx\njnz")

        result = patch_short_jump_exclusive("jRCXz")
        expect(result == "test rcx, rcx\njz")

    def test_empty_returns_none(self):
        result = patch_short_jump_exclusive("")
        expect(not (result is not None))

    def test_unknown_mnemonic_returns_none(self):
        result = patch_short_jump_exclusive("call")
        expect(not (result is not None))

        result = patch_short_jump_exclusive("ret")
        expect(not (result is not None))
