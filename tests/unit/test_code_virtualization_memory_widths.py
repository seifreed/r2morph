"""Unit contracts for byte and word memory decoding and lowering."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region import extract_region
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _decode_cmp_mem,
    _decode_memory_immediate,
    _decode_memory_mov,
    _decode_memory_mov_indexed,
    _decode_op_mem,
    _decode_op_memdst,
)
from r2morph.mutations.code_virtualization_region_microops import _vpop_partial_handler_asm
from tests.utils.assertions import expect

_EXPECTED_STOREI_BYTE_SIZE = 11


def test_memory_mov_decodes_byte_load_with_low_byte_width() -> None:
    expect(_decode_memory_mov("mov al, byte ptr [rsp+8]") == ("load", 0, 4, 8, 8))


def test_memory_mov_decodes_word_store_with_low_word_width() -> None:
    expect(_decode_memory_mov("mov word ptr [rbp-2], ax") == ("store", 0, 5, -2, 16))


def test_memory_mov_indexed_decodes_byte_load_with_low_byte_width() -> None:
    expect(_decode_memory_mov_indexed("mov dl, byte ptr [rbx+rcx*2+4]") == ("loadidx", 2, 3, 1, 1, 4, 8))


def test_memory_arithmetic_decodes_byte_register_source_with_low_byte_width() -> None:
    expect(_decode_op_mem("add al, byte ptr [rsp+8]", "add", 0x1000, 3) == ("opmem", "add", 0, 4, 8, 8))


def test_memory_arithmetic_decodes_word_memory_destination_with_low_word_width() -> None:
    expect(_decode_op_memdst("add word ptr [rbp-2], ax", "add", 0x1000, 3) == ("opmemdst", "add", 0, 5, -2, 16))


def test_memory_compare_decodes_byte_register_with_low_byte_width() -> None:
    expect(_decode_cmp_mem("cmp al, byte ptr [rsp+8]", 0x1000, 3) == ("cmpmem", 0, 4, 8, 8))


def test_memory_immediate_decodes_direct_store_with_width() -> None:
    expect(_decode_memory_immediate("mov word ptr [rbp-2], 0x1234", 0x1000, 7) == ("storei", 0x1234, 5, -2, 16))


def test_memory_immediate_decodes_rip_relative_store() -> None:
    expect(
        _decode_memory_immediate("mov dword ptr [rip+0x20], 0x12345678", 0x1000, 6)
        == ("storeirip", 0x12345678, 0x1026, 32)
    )


def test_memory_immediate_decodes_indexed_store() -> None:
    expect(_decode_memory_immediate("mov byte ptr [rbx+rcx*4+8], 7", 0x1000, 5) == ("storeiidx", 7, 3, 1, 2, 8, 8))


def test_memory_immediate_rejects_qword_value_outside_native_immediate() -> None:
    expect(_decode_memory_immediate("mov qword ptr [rax], 0x123456789", 0x1000, 7) is None)


def test_memory_immediate_item_size_includes_masked_immediate() -> None:
    expect(_item_size(("storei", 7, 3, 8, 8)) == _EXPECTED_STOREI_BYTE_SIZE)


def test_memory_region_lowers_byte_load_to_partial_pop() -> None:
    instructions = [
        {"addr": 0x1000, "size": 4, "type": "mov", "opcode": "mov al, byte ptr [rsp+8]"},
        {"addr": 0x1004, "size": 1, "type": "ret", "opcode": "ret"},
    ]
    region = extract_region(instructions)
    expect(region is not None and region.instructions[1][0] == "vpop8")


def test_partial_pop_handler_preserves_upper_destination_bits() -> None:
    expect("and r11, -256" in _vpop_partial_handler_asm("vpop8", "0x12"))
