"""Contracts for thread-local segment memory in region virtualization."""

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_memory_decoders import _decode_tls_memory_mov
from r2morph.mutations.code_virtualization_region_memory_handlers import _tls_memory_handler_asm
from tests.utils.assertions import expect


def test_tls_load_decoder_preserves_segment_and_absolute_displacement() -> None:
    item = _decode_tls_memory_mov("mov rax, qword fs:[0x28]")

    expect(item == ("tlsload", 0, "fs", None, 0x28, 64))


def test_tls_store_decoder_preserves_segment_and_base_register() -> None:
    item = _decode_tls_memory_mov("mov qword ptr gs:[rdi+8], rax")

    expect(item == ("tlsstore", 0, "gs", 7, 8, 64))


def test_tls_load_is_classified_as_a_virtualizable_memory_item() -> None:
    item = _classify({"type": "mov", "opcode": "mov rax, qword fs:[0x28]"})

    expect(item == ["tlsload", 0, "fs", None, 0x28, 64])


def test_tls_handler_uses_the_current_thread_segment_base() -> None:
    assembly = _tls_memory_handler_asm("tlsload_fs_-1_64", "r13b", "r14d", 0)

    expect("mov rax, qword ptr fs:[r10]" in assembly)
