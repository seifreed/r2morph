"""Unit tests for register-source movzx/movsx region lowering.

`movzx eax, al` / `movsx rax, cx` extend a source register's low byte or word into
a wider destination. The source's full value already lives in its context slot, so
the handler reads that slot and extends al/ax - no memory access, no flags. These
pin the decode, sizing, and flag-transparency contracts on the real lifter.
"""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_engine import decode_instruction
from r2morph.mutations.code_virtualization_region import _classify, _flag_dead_op_indices
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size


def _insn(opcode: str) -> dict[str, Any]:
    # r2 types movzx/movsx under the mov type.
    return {"type": "mov", "opcode": opcode, "addr": 0x1000, "size": 4}


def test_classify_movzx_byte_register_lowers_to_movxreg_zero_extend() -> None:
    assert _classify(_insn("movzx esi, al")) == ["movxreg", "z", 8, 32, 6, 0]


def test_classify_movsx_byte_register_records_sign_and_64bit_destination() -> None:
    assert _classify(_insn("movsx rdi, al")) == ["movxreg", "s", 8, 64, 7, 0]


def test_classify_movzx_word_register_records_16bit_source() -> None:
    assert _classify(_insn("movzx edx, cx")) == ["movxreg", "z", 16, 32, 2, 1]


def test_classify_movsx_extended_word_register_source() -> None:
    assert _classify(_insn("movsx rax, r8w")) == ["movxreg", "s", 16, 64, 0, 8]


def test_classify_movzx_high_byte_source_stays_native() -> None:
    # ah addresses bits 8-15, not the low byte the handler reads.
    assert _classify(_insn("movzx eax, ah")) is None


def test_classify_movzx_stack_pointer_source_stays_native() -> None:
    assert _classify(_insn("movzx eax, spl")) is None


def test_classify_movzx_memory_source_stays_on_the_memory_path() -> None:
    # A memory source is the existing movx (not movxreg) lowering.
    item = _classify(_insn("movzx eax, byte ptr [rbx]"))
    assert item is not None and item[0] == "movx"


def test_item_size_movxreg_is_opcode_plus_two_slots() -> None:
    assert _item_size(("movxreg", "z", 8, 32, 0, 1)) == 3


def test_flag_setting_op_survives_a_movxreg_before_a_jcc() -> None:
    # movzx/movsx set no flags, so an add's flags stay live across a movxreg to a
    # later jcc; the add must not be marked flag-dead (a movxreg is not a killer).
    add = ["op", decode_instruction("add eax, ebx")]
    items: list[list[Any]] = [
        add,
        ["movxreg", "z", 8, 32, 6, 0],
        ["jcc", "je", 0x2000],
        ["exit", 0x2000],
    ]
    assert 0 not in _flag_dead_op_indices(items)
