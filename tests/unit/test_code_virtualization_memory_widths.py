"""Unit contracts for byte and word memory decoding and lowering."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization import _decode_run_item
from r2morph.mutations.code_virtualization_engine import GP_REGISTERS, encode_bytecode
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from r2morph.mutations.code_virtualization_engine_models import VirtualizedAddress, VirtualizedMemOp
from r2morph.mutations.code_virtualization_region import _writes_register, extract_region
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_encoder import RegionEncoder
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _decode_bt,
    _decode_cmp_mem,
    _decode_cmp_memory_immediate,
    _decode_div,
    _decode_memory_immediate,
    _decode_memory_mov,
    _decode_memory_mov_indexed,
    _decode_mxcsr_memory,
    _decode_not,
    _decode_op_mem,
    _decode_op_mem_indexed,
    _decode_op_memdst,
    _decode_op_memdst_indexed,
    _decode_riprel_mov,
)
from r2morph.mutations.code_virtualization_region_memory_handlers import _mxcsr_memory_handler_asm
from r2morph.mutations.code_virtualization_region_microops import _vpop_partial_handler_asm
from r2morph.mutations.code_virtualization_region_models import RegionScheme, _op_key
from tests.utils.assertions import expect

_BYTE_WIDTH_BITS = 8
_WORD_WIDTH_BITS = 16
_TRANSFER_WIDTH_COUNT = 4
_EXPECTED_STOREI_BYTE_SIZE = 11
_EXPECTED_MXCSR_DIRECT_SIZE = 7


def test_memory_mov_decodes_byte_load_with_low_byte_width() -> None:
    expect(_decode_memory_mov("mov al, byte ptr [rsp+8]") == ("load", 0, 4, 8, 8))


def test_memory_mov_decodes_word_store_with_low_word_width() -> None:
    expect(_decode_memory_mov("mov word ptr [rbp-2], ax") == ("store", 0, 5, -2, 16))


def test_engine_memory_decoder_preserves_byte_store_width() -> None:
    item = _decode_run_item("mov byte ptr [rbp-2], al")
    expect(isinstance(item, VirtualizedMemOp) and item.width == _BYTE_WIDTH_BITS)


def test_engine_memory_decoder_preserves_word_load_width() -> None:
    item = _decode_run_item("mov ax, word ptr [rbp-2]")
    expect(isinstance(item, VirtualizedMemOp) and item.width == _WORD_WIDTH_BITS)


def test_rip_relative_memory_decoder_preserves_byte_store_width() -> None:
    expect(
        _decode_riprel_mov("mov byte ptr [rip+0x20], al", 0x1000, 6) == ("riprel_store", 0, 0x1026, _BYTE_WIDTH_BITS)
    )


def test_engine_memory_decoder_preserves_word_rip_relative_load_width() -> None:
    item = _decode_run_item("mov ax, word ptr [rip+0x20]", 0x1000, 6)
    expect(isinstance(item, VirtualizedMemOp) and item.width == _WORD_WIDTH_BITS)


def test_engine_memory_encoder_accepts_all_transfer_widths() -> None:
    scheme = build_vm_scheme(randomness.Random(20260902))
    encoded = tuple(
        encode_bytecode([VirtualizedMemOp("load", 0, VirtualizedAddress(1, 8), width)], scheme)
        for width in (_BYTE_WIDTH_BITS, _WORD_WIDTH_BITS, 32, 64)
    )
    expect(len({item[0] for item in encoded}) == 1 and len(set(encoded)) == _TRANSFER_WIDTH_COUNT)


def test_memory_classifier_decodes_absolute_load_as_fixed_address() -> None:
    expect(
        _classify(
            {
                "type": "mov",
                "opcode": "mov rax, qword ptr [0x402000]",
                "addr": 0x1000,
                "size": 7,
            }
        )
        == ["riprel_load", 0, 0x402000, 64]
    )


def test_memory_mov_indexed_decodes_byte_load_with_low_byte_width() -> None:
    expect(_decode_memory_mov_indexed("mov dl, byte ptr [rbx+rcx*2+4]") == ("loadidx", 2, 3, 1, 1, 4, 8))


def test_mxcsr_memory_decoder_decodes_direct_load() -> None:
    expect(_decode_mxcsr_memory("ldmxcsr dword ptr [rbx+8]", 0x1000, 6) == ("mxcsrload", 3, 8))


def test_mxcsr_memory_decoder_decodes_rip_relative_store() -> None:
    expect(_decode_mxcsr_memory("stmxcsr dword ptr [rip+0x20]", 0x1000, 6) == ("mxcsrstorerip", 0x1026))


def test_mxcsr_memory_decoder_decodes_indexed_load_without_base() -> None:
    expect(_decode_mxcsr_memory("ldmxcsr dword ptr [rcx*4+8]", 0x1000, 6) == ("mxcsrloadidxnb", 1, 2, 8))


def test_mxcsr_memory_decoder_decodes_indexed_store() -> None:
    expect(_decode_mxcsr_memory("stmxcsr dword ptr [rbx+rcx*4+8]", 0x1000, 6) == ("mxcsrstoreidx", 3, 1, 2, 8))


def test_mxcsr_memory_classifier_accepts_non_binary_instruction_type() -> None:
    expect(
        _classify({"type": "store", "opcode": "stmxcsr dword ptr [rax+4]", "addr": 0x1000, "size": 6})
        == ["mxcsrstore", 0, 4]
    )


def test_mxcsr_memory_items_have_address_shape_sizes() -> None:
    expect(
        tuple(
            _item_size(item)
            for item in (
                ("mxcsrload", 0, 8),
                ("mxcsrloadrip", 0x1026),
                ("mxcsrloadidxnb", 1, 2, 8),
                ("mxcsrloadidx", 3, 1, 2, 8),
            )
        )
        == (7, 6, 8, 9)
    )


def test_mxcsr_memory_encoder_emits_direct_item() -> None:
    scheme = RegionScheme(
        dup={"mxcsrload_3_8": (0,)},
        xor_key=0,
        junk_seed=0,
        slot_perm=tuple(range(16)),
        table_key=0,
    )
    encoded = RegionEncoder(scheme, [0], 0, 0).encode([("mxcsrload", 3, 8)])
    expect(len(encoded) == _EXPECTED_MXCSR_DIRECT_SIZE)


def test_mxcsr_memory_handler_emits_native_load() -> None:
    expect("ldmxcsr dword ptr [r10]" in _mxcsr_memory_handler_asm("mxcsrload_3_8", "0x12", "0x12121212"))


def test_mxcsr_memory_handler_emits_native_store_for_indexed_address() -> None:
    assembly = _mxcsr_memory_handler_asm("mxcsrstoreidx_3_1_2_8", "0x12", "0x12121212")
    expect("stmxcsr dword ptr [r10]" in assembly and "add rsi, 9" in assembly)


def test_memory_arithmetic_decodes_byte_register_source_with_low_byte_width() -> None:
    expect(_decode_op_mem("add al, byte ptr [rsp+8]", "add", 0x1000, 3) == ("opmem", "add", 0, 4, 8, 8))


def test_memory_arithmetic_decodes_word_memory_destination_with_low_word_width() -> None:
    expect(_decode_op_memdst("add word ptr [rbp-2], ax", "add", 0x1000, 3) == ("opmemdst", "add", 0, 5, -2, 16))


def test_memory_arithmetic_decodes_indexed_source_without_base() -> None:
    expect(_decode_op_mem_indexed("add rax, qword ptr [rcx*4+8]", "add") == ("opmemidxnb", "add", 0, 1, 2, 8, 64))


def test_memory_arithmetic_decodes_indexed_destination_without_base() -> None:
    expect(_decode_op_memdst_indexed("add qword ptr [rcx*4+8], rax", "add") == ("opmemdstidxnb", "add", 0, 1, 2, 8, 64))


def test_memory_compare_decodes_byte_register_with_low_byte_width() -> None:
    expect(_decode_cmp_mem("cmp al, byte ptr [rsp+8]", 0x1000, 3) == ("cmpmem", 0, 4, 8, 8))


def test_memory_compare_decodes_direct_immediate() -> None:
    expect(_decode_cmp_memory_immediate("cmp dword ptr [rbx], 0xf", 0x1000, 4) == ("cmpmemimm", 0xF, 3, 0, 32))


def test_memory_compare_decodes_rip_relative_immediate() -> None:
    expect(
        _decode_cmp_memory_immediate("cmp qword ptr [rip+0x20], 0x62", 0x1000, 8) == ("cmpriprelimm", 0x62, 0x1028, 64)
    )


def test_memory_compare_decodes_indexed_immediate_without_base() -> None:
    expect(_decode_cmp_memory_immediate("cmp dword ptr [rcx*4+8], 7", 0x1000, 6) == ("cmpmemimmidxnb", 7, 1, 2, 8, 32))


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


def test_memory_bt_decodes_direct_register_bit() -> None:
    expect(_decode_bt("bt dword ptr [rbx+8], ecx") == ("btmem", 3, 8, 1, False, 32))


def test_memory_bt_decodes_indexed_immediate_bit() -> None:
    expect(_decode_bt("bt qword ptr [rax+rcx*4+8], 65") == ("btmemidx", 0, 1, 2, 8, 65, True, 64))


def test_memory_bt_decodes_rip_relative_immediate_bit() -> None:
    expect(_decode_bt("bt dword ptr [rip+0x20], 3", 0x1000, 6) == ("btmemrip", 0x1026, 3, True, 32))


def test_memory_bt_handler_key_uses_mode_letter() -> None:
    expect(_op_key(("btmem", 3, 8, 1, False, 32)) == "btmem_r_32")


def test_memory_div_decodes_direct_signed_dword() -> None:
    expect(_decode_div("idiv dword ptr [rbx+8]") == ("divmem", "s", 3, 8, 32))


def test_memory_div_decodes_indexed_unsigned_qword() -> None:
    expect(_decode_div("div qword ptr [rax+rcx*4+8]") == ("divmemidx", "u", 0, 1, 2, 8, 64))


def test_memory_div_decodes_rip_relative_unsigned_qword() -> None:
    expect(_decode_div("div qword ptr [rip+0x20]", 0x1000, 6) == ("divmemrip", "u", 0x1026, 64))


def test_memory_div_handler_key_includes_signedness_and_width() -> None:
    expect(_op_key(("divmem", "s", 3, 8, 32)) == "divmem_s_32")


def test_memory_division_writes_implicit_registers_in_stack_model() -> None:
    expected = frozenset({GP_REGISTERS.index("rax"), GP_REGISTERS.index("rdx")})
    kinds = ("divmem", "divmemrip", "divmemidx", "divmemidxnb")

    expect(all(_writes_register((kind,)) == expected for kind in kinds))


def test_memory_not_decodes_direct_width() -> None:
    expect(_decode_not("not word ptr [rbx+8]") == ("notmem", 3, 8, 16))


def test_memory_not_decodes_indexed_without_base() -> None:
    expect(_decode_not("not byte ptr [rcx*4+8]") == ("notmemidxnb", 1, 2, 8, 8))


def test_memory_not_decodes_rip_relative_width() -> None:
    expect(_decode_not("not qword ptr [rip+0x20]", 0x1000, 7) == ("notmemrip", 0x1027, 64))
