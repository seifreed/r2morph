"""Unit tests for setcc/cmov region lowering (flag consumers).

r2 types both ``setcc`` and ``cmovcc`` as ``cmov``. The classifier lowers a
low-byte ``setcc`` and a register-to-register ``cmov`` to dedicated items whose
handlers evaluate the condition arithmetically from the captured flags slot; a
memory or high-byte operand, or an unrecognized condition, stays native. These
pin the decode, sizing, and flag-liveness contracts on the real lifter.
"""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_engine import decode_instruction
from r2morph.mutations.code_virtualization_region import _classify, _flag_dead_op_indices
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size


def _insn(opcode: str) -> dict[str, Any]:
    return {"type": "cmov", "opcode": opcode, "addr": 0x1000, "size": 4}


def test_classify_setcc_low_byte_register_lowers_to_setcc_item() -> None:
    assert _classify(_insn("sete al")) == ["setcc", "je", 0]


def test_classify_setcc_condition_alias_maps_to_canonical_condition() -> None:
    # `setnae` is the CF alias of `setb`; both collapse to the canonical `jb`.
    assert _classify(_insn("setnae bl")) == ["setcc", "jb", 3]


def test_classify_setcc_high_byte_register_stays_native() -> None:
    # ah/bh/ch/dh address bits 8-15, not the low byte the handler writes.
    assert _classify(_insn("sete ah")) is None


def test_classify_setcc_memory_destination_stays_native() -> None:
    assert _classify(_insn("sete byte ptr [rax]")) is None


def test_classify_cmov_register_pair_lowers_to_cmov_item() -> None:
    assert _classify(_insn("cmovae rax, rcx")) == ["cmov", "jae", 0, 1, 64]


def test_classify_cmov_32bit_pair_records_width_32() -> None:
    assert _classify(_insn("cmovne edi, esi")) == ["cmov", "jne", 7, 6, 32]


def test_classify_cmov_memory_source_stays_native() -> None:
    assert _classify(_insn("cmove rax, qword ptr [rbx]")) is None


def test_classify_cmov_mismatched_width_stays_native() -> None:
    assert _classify(_insn("cmove rax, ecx")) is None


def test_item_size_setcc_is_opcode_plus_one_slot() -> None:
    assert _item_size(("setcc", "je", 0)) == 2


def test_item_size_cmov_is_opcode_plus_two_slots() -> None:
    assert _item_size(("cmov", "je", 0, 1, 64)) == 3


def test_flag_setting_op_before_setcc_is_not_marked_flag_dead() -> None:
    # An add whose flags a following setcc reads must synthesize its flags, so it
    # is NOT in the flag-dead set (unlike an add followed only by a flag killer).
    add = ["op", decode_instruction("add eax, ebx")]
    items: list[list[Any]] = [add, ["setcc", "je", 0], ["exit", 0x2000]]
    assert 0 not in _flag_dead_op_indices(items)


def test_flag_setting_op_before_cmov_is_not_marked_flag_dead() -> None:
    add = ["op", decode_instruction("add eax, ebx")]
    items: list[list[Any]] = [add, ["cmov", "je", 2, 3, 64], ["exit", 0x2000]]
    assert 0 not in _flag_dead_op_indices(items)
