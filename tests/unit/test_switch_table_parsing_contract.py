from __future__ import annotations

from r2morph.analysis.switch_table_parsing import (
    classify_indirect_jump,
    match_jumptable_operands,
)


def test_switch_table_parsing_matches_jump_table_operands() -> None:
    operands = match_jumptable_operands("jmp [rax*4 + 0x405000]")

    assert operands is not None
    assert operands["displacement"] == 0x405000
    assert operands["table_address"] is None


def test_switch_table_parsing_classifies_indirect_jumps() -> None:
    jump = classify_indirect_jump(0x1000, "jmp [rax*4 + 0x405000]", 0x2000)

    assert jump is not None
    assert jump.jump_type == "jumptable"
    assert jump.address == 0x1000
