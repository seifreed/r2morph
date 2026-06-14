from __future__ import annotations

import struct

from r2morph.analysis.switch_table_models import IndirectJump, JumpTableType
from r2morph.analysis.switch_table_resolution import (
    get_jump_table_targets,
    normalize_address,
    reconstruct_switch_cases,
    resolve_jump_table,
)
from tests._doubles.in_memory_jump_table_binary import InMemoryJumpTableBinary


class _BasicBlockBinary(InMemoryJumpTableBinary):
    def __init__(self, *, bits: int, table_address: int, blob: bytes) -> None:
        super().__init__(bits=bits, table_address=table_address, blob=blob)

    def get_basic_blocks(self, _function_address: int) -> list[dict[str, int]]:
        return [{"addr": 0x5000}, {"addr": 0x5010}]


def _blob(targets: list[int]) -> bytes:
    return b"".join(struct.pack("<Q", target) for target in targets)


def _jump(**overrides: object) -> IndirectJump:
    fields: dict[str, object] = {
        "address": 0x401000,
        "instruction": "jmp qword [rax*8 + 0x9000]",
        "jump_type": "jumptable",
        "base_register": "rax",
        "index_register": "rcx",
        "scale": 8,
        "displacement": 0x9000,
        "table_address": 0x9000,
        "target_candidates": [],
        "function_address": 0x400000,
    }
    fields.update(overrides)
    return IndirectJump(**fields)


def test_switch_table_resolution_contract() -> None:
    assert normalize_address(0x7FFFFFFFFFFF, 64) == 0x7FFFFFFFFFFF

    binary = InMemoryJumpTableBinary(bits=64, table_address=0x9000, blob=_blob([0x5000, 0x5010]))
    jump = _jump()

    table = resolve_jump_table(binary, jump)
    assert table is not None
    assert table.table_type == JumpTableType.INDIRECT

    targets = get_jump_table_targets(table)
    assert targets == {0: [0x5000], 1: [0x5010]}

    cases = reconstruct_switch_cases(_BasicBlockBinary(bits=64, table_address=0x9000, blob=_blob([0x5000, 0x5010])), table, 0x400000)
    assert cases[0]["is_block_start"] is True
    assert cases[1]["is_block_start"] is True
