"""Contract tests for atomic memory exchange lowering."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region import _writes_register
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _decode_cmpxchg_memory,
    _decode_locked_memory_rmw,
    _decode_xchg_memory,
)
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    AtomicMemoryOperationConfig,
    _atomic_memory_rmw_handler_asm,
    _cmpxchg_memory_handler_asm,
    _xchg_memory_handler_asm,
    _xchg_memory_indexed_handler_asm,
)
from r2morph.mutations.code_virtualization_region_models import _op_key
from tests.utils.assertions import expect

_EXPECTED_DIRECT_ATOMIC_ITEM_SIZE = 7
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


def test_cmpxchg_memory_decoder_requires_lock_prefix() -> None:
    expect(_decode_cmpxchg_memory("cmpxchg qword ptr [rbx+8], rcx") is None)


def test_locked_memory_rmw_decoder_accepts_register_source() -> None:
    expect(
        _decode_locked_memory_rmw("lock add dword ptr [rbx+8], ecx", 0x401000, 4) == ("atomicmem", "add", 1, 3, 8, 32)
    )


def test_locked_memory_rmw_decoder_accepts_rip_relative_source() -> None:
    expect(
        _decode_locked_memory_rmw("lock sub qword ptr [rip+16], rax", 0x401000, 7)
        == ("atomicmemrip", "sub", 0, 0x401017, 64)
    )


def test_locked_memory_rmw_handler_emits_native_atomic_operation() -> None:
    assembly = _atomic_memory_rmw_handler_asm("atomicmemrip_add_32", "0x12", "0x11223344")
    expect("lock add dword ptr [r10], eax" in assembly)


def test_locked_memory_rmw_items_have_stable_handler_key_and_size() -> None:
    item = ("atomicmem", "add", 1, 3, 8, 32)
    expect(_op_key(item) == "atomicmem_add_32")
    expect(_item_size(item) == _EXPECTED_DIRECT_ATOMIC_ITEM_SIZE)


def test_cmpxchg_memory_decoder_accepts_locked_indexed_form() -> None:
    expect(
        _decode_cmpxchg_memory("lock cmpxchg dword ptr [rbx+rcx*4+16], eax") == ("cmpxchgmemidx", 0, 3, 1, 2, 16, 32)
    )


def test_cmpxchg_memory_classifier_accepts_locked_form() -> None:
    expect(
        _classify(
            {
                "type": "mov",
                "opcode": "lock cmpxchg qword ptr [rbx+8], rcx",
                "addr": 0x1000,
                "size": 5,
            }
        )
        == ["cmpxchgmem", 1, 3, 8, 64]
    )


def test_cmpxchg_memory_handler_preserves_native_compare_exchange() -> None:
    assembly = _cmpxchg_memory_handler_asm(
        AtomicMemoryOperationConfig("cmpxchgmem_64", "0x12", "0x11223344", tuple(range(16)))
    )
    expect("lock cmpxchg qword ptr [r10], rbx" in assembly)


def test_cmpxchg_memory_indexed_item_has_indexed_memory_size() -> None:
    expect(_item_size(("cmpxchgmemidx", 0, 3, 1, 2, 16, 32)) == _EXPECTED_INDEXED_XCHG_ITEM_SIZE)


def test_atomic_memory_direct_items_match_handler_byte_length() -> None:
    expect(_item_size(("xchgmem", 0, 3, 8, 64)) == _EXPECTED_DIRECT_ATOMIC_ITEM_SIZE)


def test_cmpxchg_memory_direct_item_matches_handler_byte_length() -> None:
    expect(_item_size(("cmpxchgmem", 0, 3, 8, 64)) == _EXPECTED_DIRECT_ATOMIC_ITEM_SIZE)


def test_cmpxchg_memory_writes_accumulator_and_not_source() -> None:
    expect(_writes_register(("cmpxchgmem", 1, 3, 8, 64)) == frozenset({0}))
