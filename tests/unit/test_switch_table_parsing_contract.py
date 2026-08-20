from __future__ import annotations

from r2morph.analysis.switch_table_parsing import (
    classify_indirect_jump,
    match_jumptable_operands,
)
from tests.utils.assertions import expect

_EXPECTED_JUMP_ADDRESS_4096 = 0x1000
_EXPECTED_OPERANDS_DISPLACEMENT_4214784 = 0x405000


def test_switch_table_parsing_matches_jump_table_operands() -> None:
    operands = match_jumptable_operands("jmp [rax*4 + 0x405000]")

    expect(operands is not None)
    expect(operands["displacement"] == _EXPECTED_OPERANDS_DISPLACEMENT_4214784)
    expect(not (operands["table_address"] is not None))


def test_switch_table_parsing_classifies_indirect_jumps() -> None:
    jump = classify_indirect_jump(0x1000, "jmp [rax*4 + 0x405000]", 0x2000)

    expect(jump is not None)
    expect(jump.jump_type == "jumptable")
    expect(jump.address == _EXPECTED_JUMP_ADDRESS_4096)
