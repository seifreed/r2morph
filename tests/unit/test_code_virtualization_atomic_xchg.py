"""Contract tests for atomic memory exchange lowering."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_memory_decoders import _decode_xchg_memory
from r2morph.mutations.code_virtualization_region_memory_handlers import _xchg_memory_handler_asm
from tests.utils.assertions import expect


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
