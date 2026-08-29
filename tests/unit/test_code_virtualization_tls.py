"""Contracts for thread-local segment memory in region virtualization."""

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
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


def test_tls_indexed_load_decoder_preserves_base_and_index() -> None:
    item = _decode_tls_memory_mov("mov rax, qword ptr gs:[rdi+rcx*8+16]")

    expect(item == ("tlsloadidx", 0, "gs", 7, 1, 3, 16, 64))


def test_tls_no_base_indexed_store_decoder_uses_short_layout() -> None:
    item = _decode_tls_memory_mov("mov dword ptr fs:[rcx*4+8], eax")

    expect(item == ("tlsstoreidxnb", 0, "fs", -1, 1, 2, 8, 32))


def test_tls_memory_item_sizes_match_handler_advance() -> None:
    expect(
        (
            _item_size(("tlsload", 0, "fs", None, 40, 64)),
            _item_size(("tlsload", 0, "fs", 7, 40, 64)),
            _item_size(("tlsloadidxnb", 0, "fs", -1, 1, 3, 40, 64)),
            _item_size(("tlsloadidx", 0, "fs", 7, 1, 3, 40, 64)),
        )
        == (6, 7, 8, 9)
    )


def test_tls_indexed_handler_keeps_segment_override() -> None:
    assembly = _tls_memory_handler_asm("tlsloadidxnb_gs_64", "r13b", "r14d", 0)

    expect("mov rax, qword ptr gs:[r10]" in assembly)
