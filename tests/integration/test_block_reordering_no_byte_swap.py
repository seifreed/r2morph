"""Regression: block reordering must never relocate block bytes.

``dataset/elf_blockswap_x86_64`` has two adjacent equal-size basic blocks that each
end in a relative ``jmp``. The removed byte-swap path used to exchange their raw
bytes, leaving the relative jump offsets pointing at the wrong addresses. Block
reordering must leave the original block bytes in place (it only inserts jumps).
"""

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.block_reordering import BlockReorderingPass

_FIXTURE = Path("dataset/elf_blockswap_x86_64")
_BLOCK_A_ADDR = 0x1005  # `mov eax, 1; jmp done`
_BLOCK_A_HEAD = bytes.fromhex("b801")  # mov eax, 1


def test_block_reordering_never_relocates_relative_jump_blocks(tmp_path: Path):
    if not _FIXTURE.exists():
        pytest.skip("block-swap fixture not available")
    for seed in range(1, 21):
        temp = tmp_path / f"bs_{seed}"
        shutil.copy(_FIXTURE, temp)
        with Binary(temp, writable=True) as binary:
            binary.analyze()
            pass_obj = BlockReorderingPass(config={"probability": 1.0, "seed": seed})
            pass_obj.force_different = True
            pass_obj.apply(binary)
            head = binary.read_bytes(_BLOCK_A_ADDR, 2)
        assert head == _BLOCK_A_HEAD, f"block bytes relocated at seed {seed}: {head.hex()}"
