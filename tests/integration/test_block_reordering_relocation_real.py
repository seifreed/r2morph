"""Regression: block reordering relocates blocks while preserving semantics.

Block reordering physically permutes basic blocks and re-encodes every control
transfer for the new layout. The historical corruption modes were: relative
jumps left pointing at the wrong (or out-of-bounds) address, instructions
overwritten by an inserted jump, and a fall-through successor skipped. These
tests pin the contract with a static interpreter that runs the actual control
flow of the original and the reordered binary and asserts the same exit code —
the only thing that ultimately matters.
"""

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.block_reordering import BlockReorderingPass
from tests.utils.assertions import expect

_EXPECTED_REGS_EAX_60 = 60


_JUMPCHAIN = Path("fixtures/dataset/elf_jumpchain_x86_64")
_BLOCKSWAP = Path("fixtures/dataset/elf_blockswap_x86_64")
_ENTRY = 0x1000
_MAX_STEPS = 64


def _operand_value(token: str, regs: dict[str, int]) -> int:
    token = token.strip().rstrip(";").strip()
    if token in regs:
        return regs[token]
    return int(token, 0)


def _interpret(binary: Binary, entry: int, edi_in: int) -> int:
    """Execute the fixture's instruction subset and return the exit code.

    Follows real control flow (jmp / conditional / fall-through) so a corrupt
    jump offset or a skipped block changes the result.
    """
    regs = {"eax": 0, "ecx": 0, "edx": 0, "edi": edi_in & 0xFFFFFFFF}
    zero_flag = False
    addr = entry
    for _ in range(_MAX_STEPS):
        insn = binary.r2.cmdj(f"pdj 1 @ 0x{addr:x}")[0]
        disasm = insn["disasm"].split(";")[0].strip()
        mnemonic = disasm.split()[0]
        instruction_size = len(bytes.fromhex(insn["bytes"])) if insn.get("bytes") else insn["size"]

        if mnemonic == "jmp":
            addr = insn["jump"]
            continue
        if mnemonic in ("je", "jz", "jne", "jnz"):
            taken = zero_flag if mnemonic in ("je", "jz") else not zero_flag
            addr = insn["jump"] if taken else addr + instruction_size
            continue
        if mnemonic == "syscall":
            expect(regs["eax"] == _EXPECTED_REGS_EAX_60, "fixture must exit via sys_exit (eax=60)")
            return regs["edi"] & 0xFF
        if mnemonic == "ret":
            return regs["edi"] & 0xFF

        operands = disasm[len(mnemonic) :].split(",")
        dest = operands[0].strip()
        if mnemonic == "mov":
            regs[dest] = _operand_value(operands[1], regs) & 0xFFFFFFFF
        elif mnemonic == "sub":
            regs[dest] = (regs[dest] - _operand_value(operands[1], regs)) & 0xFFFFFFFF
        elif mnemonic == "add":
            regs[dest] = (regs[dest] + _operand_value(operands[1], regs)) & 0xFFFFFFFF
        elif mnemonic == "cmp":
            zero_flag = regs[dest] == (_operand_value(operands[1], regs) & 0xFFFFFFFF)
        addr += instruction_size

    raise AssertionError("interpreter exceeded step budget (possible bad control flow)")


def _reorder(fixture: Path, tmp_path: Path, seed: int) -> tuple[Binary, bool]:
    temp = tmp_path / f"{fixture.name}_{seed}"
    shutil.copy(fixture, temp)
    binary = Binary(temp, writable=True)
    binary.open()
    binary.analyze()
    pass_obj = BlockReorderingPass(config={"probability": 1.0, "seed": seed, "max_functions": 2})
    result = pass_obj.apply(binary)
    return binary, result["functions_mutated"] > 0


def _reference_exit(fixture: Path, tmp_path: Path, edi_in: int) -> int:
    temp = tmp_path / f"{fixture.name}_ref"
    shutil.copy(fixture, temp)
    with Binary(temp, writable=True) as binary:
        binary.analyze()
        return _interpret(binary, _ENTRY, edi_in)


def _assert_semantics_preserved(fixture: Path, tmp_path: Path, edi_in: int) -> int:
    """Reorder under every seed and assert the exit code never changes.

    Returns how many seeds actually produced a reordering so callers can assert
    the test was not vacuous.
    """
    expected = _reference_exit(fixture, tmp_path, edi_in)
    reordered_count = 0
    for seed in range(0, 25):
        binary, reordered = _reorder(fixture, tmp_path, seed)
        try:
            got = _interpret(binary, _ENTRY, edi_in)
        finally:
            binary.close()
        reordered_count += int(reordered)
        expect(got == expected, f"exit code changed after reorder (seed {seed}): {got} != {expected}")
    return reordered_count


def test_jumpchain_reorder_preserves_exit_code(tmp_path: Path) -> None:
    if not _JUMPCHAIN.exists():
        pytest.skip("jump-chain fixture not available")
    reordered = _assert_semantics_preserved(_JUMPCHAIN, tmp_path, edi_in=0)
    expect(not (reordered <= 0), "no seed reordered the jump-chain fixture; test is vacuous")


def test_conditional_fixture_reorder_preserves_exit_code(tmp_path: Path) -> None:
    if not _BLOCKSWAP.exists():
        pytest.skip("block-swap fixture not available")
    # edi starts 0 -> `cmp edi,0; je equal` is taken -> eax=2 -> exit(2).
    reordered = _assert_semantics_preserved(_BLOCKSWAP, tmp_path, edi_in=0)
    expect(not (reordered <= 0), "no seed reordered the conditional fixture; test is vacuous")


def test_reorder_preserves_function_byte_budget(tmp_path: Path) -> None:
    if not _JUMPCHAIN.exists():
        pytest.skip("jump-chain fixture not available")
    binary, reordered = _reorder(_JUMPCHAIN, tmp_path, seed=0)
    try:
        expect(reordered, "seed 0 was expected to reorder the jump-chain fixture")
        func = binary.get_functions()[0]
        blocks = binary.get_basic_blocks(func["addr"])
        start = min(b["addr"] for b in blocks)
        end = max(b["addr"] + b["size"] for b in blocks)
        expect(end - start == func["size"], "reordering changed the function byte budget")
    finally:
        binary.close()
