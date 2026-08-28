"""Contract tests for atomic memory exchange lowering."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region import _writes_register
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_memory_decoders import _decode_xchg_memory
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    _xchg_memory_handler_asm,
    _xchg_memory_indexed_handler_asm,
)
from tests.utils.assertions import expect

_EXPECTED_INDEXED_XCHG_ITEM_SIZE = 9


def test_xchg_memory_decoder_preserves_register_and_address_slots() -> None:
    expect(_decode_xchg_memory("xchg qword ptr [rbx+8], rax") == ("xchgmem", 0, 3, 8, 64))


def test_xchg_memory_classifier_accepts_vector_independent_instruction() -> None:
    expect(
        _classify(
            {
                "type": "mov",
                "opcode": "xchg qword ptr [rbx+8], rax",
                "addr": 0x1000,
                "size": 4,
            }
        )
        == ["xchgmem", 0, 3, 8, 64]
    )


def test_xchg_memory_handler_emits_native_locked_exchange() -> None:
    assembly = _xchg_memory_handler_asm("xchgmem_64", "byte ptr [rsp+136]", "0x1122334455667788")
    expect("xchg qword ptr [r10], rax" in assembly)


def test_xchg_memory_decoder_accepts_scaled_index_address() -> None:
    expect(_decode_xchg_memory("xchg qword ptr [rbx+rcx*8+16], rax") == ("xchgmemidx", 0, 3, 1, 3, 16, 64))


def test_xchg_memory_decoder_rejects_indexed_width_mismatch() -> None:
    expect(_decode_xchg_memory("xchg dword ptr [rbx+rcx*8+16], rax") is None)


def test_xchg_memory_classifier_accepts_scaled_index_address() -> None:
    expect(
        _classify(
            {
                "type": "mov",
                "opcode": "xchg qword ptr [rbx+rcx*8+16], rax",
                "addr": 0x1000,
                "size": 5,
            }
        )
        == ["xchgmemidx", 0, 3, 1, 3, 16, 64]
    )


def test_xchg_memory_indexed_item_has_indexed_memory_size() -> None:
    expect(_item_size(("xchgmemidx", 0, 3, 1, 3, 16, 64)) == _EXPECTED_INDEXED_XCHG_ITEM_SIZE)


def test_xchg_memory_indexed_invalidates_the_register_slot() -> None:
    expect(_writes_register(("xchgmemidx", 0, 3, 1, 3, 16, 64)) == frozenset({0}))


def test_xchg_memory_indexed_handler_emits_native_locked_exchange() -> None:
    assembly = _xchg_memory_indexed_handler_asm("xchgmemidx_64", "0x12", "0x11223344")
    expect("xchg qword ptr [r10], rax" in assembly)
