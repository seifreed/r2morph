"""Unit contracts for byte and word memory decoding and lowering."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region import extract_region
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _decode_memory_mov,
    _decode_memory_mov_indexed,
)
from r2morph.mutations.code_virtualization_region_microops import _vpop_partial_handler_asm
from tests.utils.assertions import expect


def test_memory_mov_decodes_byte_load_with_low_byte_width() -> None:
    expect(_decode_memory_mov("mov al, byte ptr [rsp+8]") == ("load", 0, 4, 8, 8))


def test_memory_mov_decodes_word_store_with_low_word_width() -> None:
    expect(_decode_memory_mov("mov word ptr [rbp-2], ax") == ("store", 0, 5, -2, 16))


def test_memory_mov_indexed_decodes_byte_load_with_low_byte_width() -> None:
    expect(_decode_memory_mov_indexed("mov dl, byte ptr [rbx+rcx*2+4]") == ("loadidx", 2, 3, 1, 1, 4, 8))


def test_memory_region_lowers_byte_load_to_partial_pop() -> None:
    instructions = [
        {"addr": 0x1000, "size": 4, "type": "mov", "opcode": "mov al, byte ptr [rsp+8]"},
        {"addr": 0x1004, "size": 1, "type": "ret", "opcode": "ret"},
    ]
    region = extract_region(instructions)
    expect(region is not None and region.instructions[1][0] == "vpop8")


def test_partial_pop_handler_preserves_upper_destination_bits() -> None:
    expect("and r11, -256" in _vpop_partial_handler_asm("vpop8", "0x12"))
