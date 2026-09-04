"""Contracts for locked memory-immediate virtualization."""

from r2morph.mutations.code_virtualization_region_atomic_immediate import (
    _decode_locked_memory_immediate,
)
from r2morph.mutations.code_virtualization_region_codegen import _item_size
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    MemoryImmediateOperationConfig,
    _atomic_memory_immediate_handler_asm,
)
from r2morph.mutations.code_virtualization_region_models import _op_key
from tests.utils.assertions import expect

_EXPECTED_INDEXED_ITEM_SIZE = 13


def test_locked_memory_immediate_decoder_accepts_direct_address() -> None:
    expect(
        _decode_locked_memory_immediate("lock add dword ptr [rbx+8], 3", 0x401000, 8)
        == ("atomicmemimm", "add", 3, 3, 8, 32)
    )


def test_locked_memory_immediate_decoder_accepts_rip_relative_address() -> None:
    expect(
        _decode_locked_memory_immediate("lock sub qword ptr [rip+16], 2", 0x401000, 8)
        == ("atomicmemimmrip", "sub", 2, 0x401018, 64)
    )


def test_locked_memory_immediate_decoder_accepts_indexed_address() -> None:
    expect(
        _decode_locked_memory_immediate("lock xor dword ptr [rbx+rcx*4+16], 1", 0x401000, 8)
        == ("atomicmemimmidx", "xor", 1, 3, 1, 2, 16, 32)
    )


def test_locked_memory_immediate_decoder_accepts_no_base_indexed_address() -> None:
    expect(
        _decode_locked_memory_immediate("lock or dword ptr [rcx*4+0x402000], 2", 0x401000, 8)
        == ("atomicmemimmidxnb", "or", 2, 1, 2, 0x402000, 32)
    )


def test_locked_memory_immediate_key_includes_operation_and_width() -> None:
    expect(_op_key(("atomicmemimm", "and", 7, 3, 8, 32)) == "atomicmemimm_and_32")


def test_locked_memory_immediate_item_size_includes_encoded_immediate() -> None:
    expect(_item_size(("atomicmemimmidx", "xor", 1, 3, 1, 2, 16, 32)) == _EXPECTED_INDEXED_ITEM_SIZE)


def test_locked_memory_immediate_handler_uses_native_atomic_operation() -> None:
    assembly = _atomic_memory_immediate_handler_asm(
        MemoryImmediateOperationConfig("atomicmemimm_add_32", "0x12", "0x1122334455667788", "0x11223344")
    )

    expect("lock add dword ptr [r10], eax" in assembly and "pushfq" in assembly)
