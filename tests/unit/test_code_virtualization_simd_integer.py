"""Unit contracts for integer packed XMM operations."""

from r2morph.core import randomness
from r2morph.mutations import code_virtualization_region_classification as classification
from r2morph.mutations.code_virtualization import _decode_run_item
from r2morph.mutations.code_virtualization_engine import build_vm_blob, build_vm_scheme
from r2morph.mutations.code_virtualization_engine_models import (
    VirtualizedAddress,
    VirtualizedFpPackedImmediateOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
)
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_arith_idx,
    _decode_fp_compare,
    _decode_fp_compare_idx,
    _decode_fp_packed_arith,
    _decode_fp_packed_arith_idx,
    _decode_fp_packed_immediate,
    _decode_fp_packed_indexed,
    _decode_fp_packed_mem,
    _decode_fp_vex_packed_arith,
    _decode_fp_vex_packed_immediate,
    _decode_fp_vex_packed_move,
    _decode_fp_vex_scalar_arith,
)
from r2morph.mutations.code_virtualization_region_fp_extra_decoders import _decode_fp_vex_extra
from r2morph.mutations.code_virtualization_region_fp_packed_extra import _decode_fp_packed_arith_extra
from tests.utils.assertions import expect

_EXPECTED_NON_DESTRUCTIVE_SOURCE = 2
_EXPECTED_BYTE_SHUFFLE_DESTINATION = 2
_EXPECTED_INDEX_SHIFT = 3
_EXPECTED_IMMEDIATE_SHIFT_COUNT = 5
_EXPECTED_RIP_TARGET = 0x401108


def test_decode_packed_integer_xor_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pxor xmm0, xmm1") == ("fppacked", "pxor", 0, 1))


def test_decode_packed_integer_add_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("paddd xmm0, xmm1") == ("fppacked", "paddd", 0, 1))


def test_decode_packed_integer_subtract_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("psubd xmm0, xmm1") == ("fppacked", "psubd", 0, 1))


def test_decode_packed_integer_byte_add_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("paddb xmm0, xmm1") == ("fppacked", "paddb", 0, 1))


def test_decode_packed_integer_word_subtract_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("psubw xmm0, xmm1") == ("fppacked", "psubw", 0, 1))


def test_decode_packed_integer_qword_add_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("paddq xmm0, xmm1") == ("fppacked", "paddq", 0, 1))


def test_decode_packed_integer_signed_byte_saturating_subtract_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("psubsb xmm0, xmm1") == ("fppacked", "psubsb", 0, 1))


def test_decode_vex128_signed_word_saturating_subtract_returns_vector_item() -> None:
    expect(_decode_fp_vex_packed_arith("vpsubsw xmm0, xmm1, xmm2") == ("fppackedvex", "psubsw", 0, 1, 2))


def test_decode_vex128_horizontal_packed_operations_returns_vector_items() -> None:
    decoded = tuple(
        _decode_fp_vex_packed_arith(f"{mnemonic} xmm0, xmm1, xmm2")
        for mnemonic in ("vphaddw", "vphaddsw", "vphsubw", "vphsubsw", "vphsubd")
    )
    expect(
        decoded
        == (
            ("fppackedvex", "phaddw", 0, 1, 2),
            ("fppackedvex", "phaddsw", 0, 1, 2),
            ("fppackedvex", "phsubw", 0, 1, 2),
            ("fppackedvex", "phsubsw", 0, 1, 2),
            ("fppackedvex", "phsubd", 0, 1, 2),
        )
    )


def test_decode_vex128_unpack_operations_returns_vector_items() -> None:
    mnemonics = (
        "vpunpckldq",
        "vpunpcklqdq",
        "vpunpckhbw",
        "vpunpckhwd",
        "vpunpckhdq",
        "vpunpckhqdq",
    )
    decoded = tuple(_decode_fp_vex_packed_arith(f"{mnemonic} xmm0, xmm1, xmm2") for mnemonic in mnemonics)
    expected = tuple(("fppackedvex", mnemonic[1:], 0, 1, 2) for mnemonic in mnemonics)
    expect(decoded == expected)


def test_decode_packed_integer_multiply_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pmulld xmm0, xmm1") == ("fppacked", "pmulld", 0, 1))


def test_decode_packed_integer_unsigned_even_multiply_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pmuludq xmm0, xmm1") == ("fppacked", "pmuludq", 0, 1))


def test_decode_packed_integer_minimum_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pminsd xmm0, xmm1") == ("fppacked", "pminsd", 0, 1))


def test_decode_packed_integer_compare_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pcmpeqd xmm0, xmm1") == ("fppacked", "pcmpeqd", 0, 1))


def test_decode_packed_integer_word_equal_compare_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pcmpeqw xmm0, xmm1") == ("fppacked", "pcmpeqw", 0, 1))


def test_decode_packed_integer_word_greater_compare_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pcmpgtw xmm0, xmm1") == ("fppacked", "pcmpgtw", 0, 1))


def test_decode_legacy_byte_shuffle_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith_extra("pshufb xmm2, xmm3") == ("fppacked", "pshufb", 2, 3))


def test_decode_packed_integer_shift_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pslld xmm0, xmm1") == ("fppacked", "pslld", 0, 1))


def test_decode_packed_integer_unsigned_maximum_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith_extra("pmaxub xmm0, xmm1") == ("fppacked", "pmaxub", 0, 1))


def test_decode_packed_integer_immediate_shift_returns_item() -> None:
    expect(_decode_fp_packed_immediate("pslld xmm2, 5") == ("fppackedimm", "pslld", 2, 5))


def test_decode_engine_packed_integer_immediate_shift_returns_item() -> None:
    item = _decode_run_item("pslld xmm2, 5")

    expect(isinstance(item, VirtualizedFpPackedImmediateOp) and item.immediate == _EXPECTED_IMMEDIATE_SHIFT_COUNT)


def test_decode_packed_integer_immediate_shuffle_returns_item() -> None:
    expect(_decode_fp_packed_immediate("pshufd xmm2, 0x1b") == ("fppackedimm", "pshufd", 2, 0x1B))


def test_decode_packed_integer_saturating_add_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("paddusb xmm0, xmm1") == ("fppacked", "paddusb", 0, 1))


def test_decode_packed_integer_average_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pavgw xmm0, xmm1") == ("fppacked", "pavgw", 0, 1))


def test_decode_packed_integer_unpack_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("punpcklbw xmm0, xmm1") == ("fppacked", "punpcklbw", 0, 1))


def test_decode_aligned_packed_integer_move_returns_memory_item() -> None:
    expect(_decode_fp_packed_mem("movdqa xmm0, xmmword ptr [rax]") == ("fppload", 0, 0, 0))


def test_decode_packed_vector_no_base_indexed_move_returns_item() -> None:
    expect(
        _decode_fp_packed_indexed("movups xmm0, xmmword ptr [rcx*8+0x402000]") == ("fpploadidxnb", 0, 1, 3, 0x402000)
    )


def test_decode_packed_vector_no_base_indexed_arithmetic_returns_item() -> None:
    expect(
        _decode_fp_packed_arith_idx("paddd xmm0, xmmword ptr [rcx*8+0x402000]")
        == ("fppackedmemidxnb", "paddd", 0, 1, 3, 0x402000)
    )


def test_decode_scalar_fp_no_base_indexed_arithmetic_returns_item() -> None:
    expect(
        _decode_fp_arith_idx("addsd xmm0, qword ptr [rcx*8+0x402000]")
        == ("fparithmemidxnb", "add", 0, -1, 1, 3, 0x402000, 64)
    )


def test_decode_scalar_fp_indexed_compare_returns_item() -> None:
    expect(
        _decode_fp_compare_idx("ucomisd xmm0, qword ptr [rcx*8+0x402000]")
        == ("fpcmpmemidxnb", "ucomisd", 0, -1, 1, 3, 0x402000, 64)
    )


def test_packed_no_base_indexed_items_use_eight_byte_encoding() -> None:
    expect(
        (
            _item_size(("fpploadidxnb", 0, 1, 3, 0x402000)),
            _item_size(("fppstoreidxnb", 0, 1, 3, 0x402000)),
            _item_size(("fppackedmemidxnb", "paddd", 0, 1, 3, 0x402000)),
            _item_size(("fparithmemidxnb", "add", 0, -1, 1, 3, 0x402000, 64)),
            _item_size(("fpcmpmemidxnb", "ucomisd", 0, -1, 1, 3, 0x402000, 64)),
        )
        == (8, 8, 8, 8, 8)
    )


def test_decode_packed_test_returns_flag_compare_item() -> None:
    expect(_decode_fp_compare("ptest xmm0, xmm1") == ("fpcmp", "ptest", 0, 1))


def test_decode_vex128_packed_test_returns_flag_compare_item() -> None:
    expect(_decode_fp_compare("vptest xmm2, xmm3") == ("fpcmp", "vptest", 2, 3))


def test_decode_vex256_packed_test_returns_flag_compare_item() -> None:
    expect(_decode_fp_compare("vptest ymm2, ymm3") == ("fpcmpvex256", "vptest", 2, 3))


def test_decode_vex128_float_test_returns_flag_compare_item() -> None:
    expect(_decode_fp_compare("vtestps xmm2, xmm3") == ("fpcmp", "vtestps", 2, 3))


def test_decode_vex256_double_test_returns_flag_compare_item() -> None:
    expect(_decode_fp_compare("vtestpd ymm2, ymm3") == ("fpcmpvex256", "vtestpd", 2, 3))


def test_decode_vex128_packed_float_add_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vaddps xmm0, xmm1, xmm2") == ("fppackedvex", "addps", 0, 1, 2))


def test_decode_vex128_horizontal_dword_add_returns_three_operand_item() -> None:
    item = _decode_run_item("vphaddd xmm0, xmm1, xmm2")
    expect(
        isinstance(item, VirtualizedFpPackedOp)
        and item.vex
        and item.mnemonic == "vphaddd"
        and item.dst_index == 0
        and item.src1_index == 1
        and item.src_index == _EXPECTED_NON_DESTRUCTIVE_SOURCE
    )


def test_decode_vex256_packed_float_add_is_rejected() -> None:
    expect(_decode_fp_vex_packed_arith("vaddps ymm0, ymm1, ymm2") is None)


def test_decode_vex128_packed_move_returns_upper_clearing_item() -> None:
    expect(_decode_fp_vex_packed_move("vmovups xmm3, xmm0") == ("fpmovvex", "full", 3, 0))


def test_decode_engine_vex128_packed_add_uses_existing_source_as_destination() -> None:
    item = _decode_run_item("vaddps xmm0, xmm0, xmm1")
    expect(isinstance(item, VirtualizedFpPackedOp) and item.vex)


def test_decode_engine_vex128_packed_add_preserves_non_destructive_sources() -> None:
    item = _decode_run_item("vaddps xmm0, xmm1, xmm2")
    expect(
        isinstance(item, VirtualizedFpPackedOp)
        and item.vex
        and item.mnemonic == "vaddps"
        and item.dst_index == 0
        and item.src1_index == 1
        and item.src_index == _EXPECTED_NON_DESTRUCTIVE_SOURCE
    )


def test_decode_engine_vex128_byte_shuffle_returns_packed_item() -> None:
    item = _decode_run_item("vpshufb xmm2, xmm0, xmm1")
    expect(
        isinstance(item, VirtualizedFpPackedOp)
        and item.vex
        and item.mnemonic == "vpshufb"
        and item.dst_index == _EXPECTED_BYTE_SHUFFLE_DESTINATION
        and item.src1_index == 0
        and item.src_index == 1
    )


def test_decode_engine_legacy_byte_shuffle_returns_packed_item() -> None:
    item = _decode_run_item("pshufb xmm2, xmm0")
    expect(
        isinstance(item, VirtualizedFpPackedOp)
        and item.mnemonic == "pshufb"
        and item.dst_index == _EXPECTED_BYTE_SHUFFLE_DESTINATION
    )


def test_decode_engine_vex256_byte_shuffle_is_rejected_by_linear_engine() -> None:
    expect(_decode_run_item("vpshufb ymm2, ymm0, ymm1") is None)


def test_decode_engine_packed_indexed_move_uses_indexed_memory_item() -> None:
    item = _decode_run_item("movups xmm0, xmmword ptr [rax + rcx*8 + 0x402000]")
    expect(
        isinstance(item, VirtualizedFpPackedMemOp)
        and item.kind == "fpploadidx"
        and item.base_index == 0
        and item.index_index == 1
        and item.scale == _EXPECTED_INDEX_SHIFT
    )


def test_decode_engine_packed_no_base_indexed_move_uses_indexed_memory_item() -> None:
    item = _decode_run_item("movups xmm0, xmmword ptr [rcx*8 + 0x402000]")
    expect(
        isinstance(item, VirtualizedFpPackedMemOp)
        and item.kind == "fpploadidxnb"
        and item.base_index == -1
        and item.index_index == 1
        and item.scale == _EXPECTED_INDEX_SHIFT
    )


def test_decode_engine_packed_rip_relative_move_uses_rip_memory_item() -> None:
    item = _decode_run_item("movups xmm0, xmmword ptr [rip + 0x100]", 0x401000, 8)
    expect(
        isinstance(item, VirtualizedFpPackedMemOp)
        and item.kind == "fpploadrip"
        and item.base_index == -1
        and item.disp == _EXPECTED_RIP_TARGET
    )


def test_engine_assembles_packed_indexed_memory_moves() -> None:
    scheme = build_vm_scheme(randomness.Random(20260830))
    item = VirtualizedFpPackedMemOp("fpploadidxnb", 0, VirtualizedAddress(-1, 0x402000, 1, 4))
    expect(build_vm_blob([item], 0x500000, 0x401000, scheme) is not None)


def test_engine_assembles_packed_immediate_shift() -> None:
    scheme = build_vm_scheme(randomness.Random(20260830))
    item = VirtualizedFpPackedImmediateOp("pslld", 0, 5)

    expect(build_vm_blob([item], 0x500000, 0x401000, scheme) is not None)


def test_engine_assembles_packed_rip_relative_memory_moves() -> None:
    scheme = build_vm_scheme(randomness.Random(20260830))
    item = VirtualizedFpPackedMemOp("fpploadrip", 0, VirtualizedAddress(-1, _EXPECTED_RIP_TARGET))
    expect(build_vm_blob([item], 0x500000, 0x401000, scheme) is not None)


def test_engine_assembles_vex128_even_dword_multiply() -> None:
    scheme = build_vm_scheme(randomness.Random(20260910))
    item = VirtualizedFpPackedOp("vpmuldq", 0, 2, vex=True, src1_index=1)
    expect(build_vm_blob([item], 0x500000, 0x401000, scheme) is not None)


def test_engine_assembles_vex128_unsigned_even_dword_multiply() -> None:
    scheme = build_vm_scheme(randomness.Random(20260911))
    item = VirtualizedFpPackedOp("vpmuludq", 0, 2, vex=True, src1_index=1)
    expect(build_vm_blob([item], 0x500000, 0x401000, scheme) is not None)


def test_decode_vex128_unsigned_even_dword_multiply_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vpmuludq xmm2, xmm0, xmm1") == ("fppackedvex", "pmuludq", 2, 0, 1))


def test_decode_vex128_packed_minimum_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vminps xmm0, xmm0, xmm1") == ("fppackedvex", "minps", 0, 0, 1))


def test_decode_vex128_packed_maximum_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vmaxps xmm0, xmm0, xmm1") == ("fppackedvex", "maxps", 0, 0, 1))


def test_decode_vex128_packed_single_sqrt_returns_unary_item() -> None:
    expect(_decode_fp_vex_packed_arith("vsqrtps xmm2, xmm1") == ("fppackedvex", "sqrtps", 2, 2, 1))


def test_decode_vex128_packed_double_sqrt_returns_unary_item() -> None:
    expect(_decode_fp_vex_packed_arith("vsqrtpd xmm2, xmm1") == ("fppackedvex", "sqrtpd", 2, 2, 1))


def test_decode_vex128_float_xor_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vxorps xmm2, xmm0, xmm1") == ("fppackedvex", "xorps", 2, 0, 1))


def test_decode_vex128_integer_xor_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vpxor xmm2, xmm0, xmm1") == ("fppackedvex", "pxor", 2, 0, 1))


def test_decode_destructive_vex128_integer_xor_preserves_vex_semantics() -> None:
    item = _decode_run_item("vpxor xmm0, xmm0, xmm1")

    expect(isinstance(item, VirtualizedFpPackedOp) and item.mnemonic == "vpxor" and item.src1_index == 0 and item.vex)


def test_decode_vex128_byte_shuffle_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_extra("vpshufb xmm2, xmm0, xmm1") == ("fppackedvex", "pshufb", 2, 0, 1))


def test_decode_vex128_unsigned_word_pack_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_extra("vpackusdw xmm2, xmm0, xmm1") == ("fppackedvex", "packusdw", 2, 0, 1))


def test_decode_vex256_byte_shuffle_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_extra("vpshufb ymm2, ymm0, ymm1") == ("fppackedvex256", "pshufb", 2, 0, 1))


def test_classify_vex128_byte_shuffle_selects_region_item() -> None:
    expect(
        classification._classify({"type": "vec", "family": "vec", "opcode": "vpshufb xmm2, xmm0, xmm1"})
        == ["fppackedvex", "pshufb", 2, 0, 1]
    )


def test_classify_vex256_byte_shuffle_selects_region_item() -> None:
    expect(
        classification._classify({"type": "vec", "family": "vec", "opcode": "vpshufb ymm2, ymm0, ymm1"})
        == ["fppackedvex256", "pshufb", 2, 0, 1]
    )


def test_decode_vex128_integer_arithmetic_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vpaddd xmm2, xmm0, xmm1") == ("fppackedvex", "paddd", 2, 0, 1))


def test_decode_vex128_variable_shift_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vpslld xmm2, xmm0, xmm1") == ("fppackedvex", "pslld", 2, 0, 1))


def test_engine_assembles_vex128_variable_shift() -> None:
    item = _decode_run_item("vpsllvd xmm2, xmm0, xmm1")

    expect(
        isinstance(item, VirtualizedFpPackedOp)
        and build_vm_blob([item], 0x500000, 0x401000, build_vm_scheme(randomness.Random(20260912))) is not None
    )


def test_engine_assembles_vex128_addsub() -> None:
    item = _decode_run_item("vaddsubps xmm2, xmm0, xmm1")

    expect(
        isinstance(item, VirtualizedFpPackedOp)
        and build_vm_blob([item], 0x500000, 0x401000, build_vm_scheme(randomness.Random(20260913))) is not None
    )


def test_decode_vex_immediate_shift_selects_128_bit_item() -> None:
    expect(_decode_fp_vex_packed_immediate("vpsrad xmm2, xmm0, 7") == ("fppackedveximm", "psrad", 2, 0, 7))


def test_decode_vex_immediate_shift_selects_256_bit_item() -> None:
    expect(_decode_fp_vex_packed_immediate("vpsrad ymm2, ymm0, 7") == ("fppackedvex256imm", "psrad", 2, 0, 7))


def test_decode_vex_immediate_shuffle_selects_256_bit_item() -> None:
    expect(_decode_fp_vex_packed_immediate("vpshufd ymm2, ymm0, 0x1b") == ("fppackedvex256imm", "pshufd", 2, 0, 0x1B))


def test_decode_vex128_scalar_arithmetic_preserves_source_one_semantics() -> None:
    expect(_decode_fp_vex_scalar_arith("vaddss xmm2, xmm0, xmm1") == ("fparithvex", "add", 2, 0, 1, 32))


def test_decode_vex128_scalar_min_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_scalar_arith("vminss xmm2, xmm0, xmm1") == ("fparithvex", "min", 2, 0, 1, 32))


def test_decode_vex128_scalar_max_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_scalar_arith("vmaxsd xmm2, xmm0, xmm1") == ("fparithvex", "max", 2, 0, 1, 64))


def test_decode_vex128_scalar_single_sqrt_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_scalar_arith("vsqrtss xmm2, xmm0, xmm1") == ("fparithvex", "sqrt", 2, 0, 1, 32))


def test_decode_vex128_scalar_double_sqrt_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_scalar_arith("vsqrtsd xmm2, xmm0, xmm1") == ("fparithvex", "sqrt", 2, 0, 1, 64))
