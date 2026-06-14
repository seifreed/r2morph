"""Contract tests for full CFF leaf helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

from r2morph.mutations.full_cff import DispatcherBlock
from r2morph.mutations.full_cff_helpers import (
    assemble_dispatcher,
    generate_arm_dispatcher,
    generate_dispatcher_code,
    generate_state_table,
    generate_x86_dispatcher,
    select_candidates,
)


class _Binary:
    def __init__(self) -> None:
        self._blocks = {
            0x1000: [object(), object(), object()],
            0x2000: [object()],
        }
        self.assembled: list[str] = []

    def get_basic_blocks(self, addr: int):
        return self._blocks[addr]

    def assemble(self, insn: str):
        table = {"mov rax, 0": b"\x48\xc7\xc0\x00\x00\x00\x00", "ret": b"\xc3", "nop": b"\x90"}
        self.assembled.append(insn)
        return table.get(insn)


def test_full_cff_helpers_cover_selection_and_generation() -> None:
    binary = _Binary()
    functions = [
        {"name": "main", "offset": 0x1000, "size": 64},
        {"name": "sym.imp.memcpy", "offset": 0x2000, "size": 64},
    ]

    candidates = select_candidates(binary, functions, min_blocks=2)
    assert candidates[0]["_block_count"] == 3

    dispatcher_blocks = [
        DispatcherBlock(state_value=0, block_address=0x1000, block_size=32, successor_states=[1, 2]),
        DispatcherBlock(state_value=1, block_address=0x1020, block_size=32, successor_states=[3]),
        DispatcherBlock(state_value=2, block_address=0x1040, block_size=32, successor_states=[3]),
        DispatcherBlock(state_value=3, block_address=0x1060, block_size=32, is_exit=True),
    ]

    state_table = generate_state_table(dispatcher_blocks)
    assert state_table[0] == (1, 2)
    assert state_table[3] == (-1, None)

    assert generate_dispatcher_code(state_table, "mips", 64) is None
    assert generate_x86_dispatcher(state_table, 64)[0] == "mov rax, 0"
    assert generate_arm_dispatcher(state_table, 64)[0] == "mov x0, #0"
    assert assemble_dispatcher(binary, ["mov rax, 0", "ret"]) is not None
    assert assemble_dispatcher(binary, ["nop"]) is not None


def test_full_cff_helpers_allow_mocked_binary_contexts() -> None:
    binary = MagicMock()
    binary.get_basic_blocks.return_value = [object(), object(), object(), object()]
    binary.assemble.return_value = b"\x90"

    candidates = select_candidates(
        binary,
        [{"name": "valid", "offset": 0x1000, "size": 100}],
        min_blocks=3,
    )
    assert candidates[0]["_block_count"] == 4
    assert assemble_dispatcher(binary, ["nop", "nop"]) == b"\x90\x90"
