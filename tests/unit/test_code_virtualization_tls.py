"""Contracts for thread-local segment memory in region virtualization."""

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_encoder import RegionEncoder
from r2morph.mutations.code_virtualization_region_memory_decoders import _decode_tls_memory_mov
from r2morph.mutations.code_virtualization_region_memory_handlers import (
    MemoryOperationConfig,
    _cmp_memory_handler_asm,
    _op_memdst_handler_asm,
    _op_memory_handler_asm,
    _tls_memory_handler_asm,
)
from r2morph.mutations.code_virtualization_region_models import RegionScheme, _op_key
from tests.utils.assertions import expect

_TLS_NO_BASE_ITEM_SIZE = 6


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


def test_tls_byte_load_preserves_upper_register_bits() -> None:
    item = _decode_tls_memory_mov("mov al, byte ptr fs:[0]")
    assembly = _tls_memory_handler_asm("tlsload_fs_-1_8", "r13b", "r14d", 0)

    expect(
        item == ("tlsload", 0, "fs", None, 0, 8)
        and "movzx eax, byte ptr fs:[r10]" in assembly
        and "and r11, -256" in assembly
    )


def test_tls_word_store_uses_the_low_word_and_segment_override() -> None:
    item = _decode_tls_memory_mov("mov word ptr gs:[4], cx")
    assembly = _tls_memory_handler_asm("tlsstore_gs_-1_16", "r13b", "r14d", 0)

    expect(item == ("tlsstore", 1, "gs", None, 4, 16) and "mov word ptr gs:[r10], ax" in assembly)


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


def test_tls_arithmetic_source_is_classified_with_segment_and_base() -> None:
    item = _classify({"type": "add", "opcode": "add rax, qword ptr fs:[rdi+8]"})

    expect(item == ["tlsopmem", "add", 0, "fs", 7, 8, 64])


def test_tls_arithmetic_destination_is_classified_as_read_modify_write() -> None:
    item = _classify({"type": "xor", "opcode": "xor dword ptr gs:[0x20], eax"})

    expect(item == ["tlsopmemdst", "xor", 0, "gs", None, 0x20, 32])


def test_tls_compare_is_classified_with_current_thread_addressing() -> None:
    item = _classify({"type": "cmp", "opcode": "cmp rax, qword ptr fs:[0x28]"})

    expect(item == ["tlscmp", 0, "fs", None, 0x28, 64])


def test_tls_arithmetic_handlers_keep_segment_override_for_reads_and_writes() -> None:
    config = MemoryOperationConfig("tlsopmem_add_fs_-1_64", "r13b", "r14d")
    source = _op_memory_handler_asm(config)
    destination = _op_memdst_handler_asm(MemoryOperationConfig("tlsopmemdst_xor_gs_-1_32", "r13b", "r14d"))

    expect("mov rax, qword ptr fs:[r10]" in source and "mov dword ptr gs:[r12], r10d" in destination)


def test_tls_compare_handler_reads_through_segment_override() -> None:
    assembly = _cmp_memory_handler_asm(MemoryOperationConfig("tlscmp_fs_-1_64", "r13b", "r14d"))

    expect("mov rax, qword ptr fs:[r10]" in assembly)


def test_tls_arithmetic_key_preserves_segment_and_no_base_layout() -> None:
    item = ("tlsopmem", "add", 0, "fs", None, 8, 64)

    expect(_op_key(item) == "tlsopmem_add_fs_None_64")


def test_tls_arithmetic_no_base_item_uses_short_handler_advance() -> None:
    expect(_item_size(("tlsopmem", "add", 0, "fs", None, 8, 64)) == _TLS_NO_BASE_ITEM_SIZE)


def test_tls_arithmetic_encoder_emits_the_segment_memory_layout() -> None:
    scheme = RegionScheme({"tlsopmem_add_fs_None_64": (0,)}, 0, 0, tuple(range(16)), 0)
    encoded = RegionEncoder(scheme, [0], 0, 0).encode([("tlsopmem", "add", 0, "fs", None, 8, 64)])

    expect(len(encoded) == _TLS_NO_BASE_ITEM_SIZE)
