"""Unit contracts for integer packed XMM operations."""

from r2morph.mutations.code_virtualization import _decode_run_item
from r2morph.mutations.code_virtualization_engine_models import VirtualizedFpPackedOp
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_compare,
    _decode_fp_packed_arith,
    _decode_fp_packed_mem,
    _decode_fp_vex_packed_arith,
    _decode_fp_vex_packed_move,
    _decode_fp_vex_scalar_arith,
)
from tests.utils.assertions import expect


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


def test_decode_packed_integer_multiply_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pmulld xmm0, xmm1") == ("fppacked", "pmulld", 0, 1))


def test_decode_packed_integer_minimum_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pminsd xmm0, xmm1") == ("fppacked", "pminsd", 0, 1))


def test_decode_packed_integer_compare_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pcmpeqd xmm0, xmm1") == ("fppacked", "pcmpeqd", 0, 1))


def test_decode_packed_integer_shift_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pslld xmm0, xmm1") == ("fppacked", "pslld", 0, 1))


def test_decode_packed_integer_saturating_add_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("paddusb xmm0, xmm1") == ("fppacked", "paddusb", 0, 1))


def test_decode_packed_integer_average_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("pavgw xmm0, xmm1") == ("fppacked", "pavgw", 0, 1))


def test_decode_packed_integer_unpack_returns_vector_item() -> None:
    expect(_decode_fp_packed_arith("punpcklbw xmm0, xmm1") == ("fppacked", "punpcklbw", 0, 1))


def test_decode_aligned_packed_integer_move_returns_memory_item() -> None:
    expect(_decode_fp_packed_mem("movdqa xmm0, xmmword ptr [rax]") == ("fppload", 0, 0, 0))


def test_decode_packed_test_returns_flag_compare_item() -> None:
    expect(_decode_fp_compare("ptest xmm0, xmm1") == ("fpcmp", "ptest", 0, 1))


def test_decode_vex128_packed_float_add_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vaddps xmm0, xmm1, xmm2") == ("fppackedvex", "addps", 0, 1, 2))


def test_decode_vex256_packed_float_add_is_rejected() -> None:
    expect(_decode_fp_vex_packed_arith("vaddps ymm0, ymm1, ymm2") is None)


def test_decode_vex128_packed_move_returns_upper_clearing_item() -> None:
    expect(_decode_fp_vex_packed_move("vmovups xmm3, xmm0") == ("fpmovvex", "full", 3, 0))


def test_decode_engine_vex128_packed_add_uses_existing_source_as_destination() -> None:
    item = _decode_run_item("vaddps xmm0, xmm0, xmm1")
    expect(isinstance(item, VirtualizedFpPackedOp) and item.vex)


def test_decode_engine_vex128_packed_add_rejects_non_destructive_source_form() -> None:
    expect(_decode_run_item("vaddps xmm0, xmm1, xmm2") is None)


def test_decode_vex128_packed_minimum_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vminps xmm0, xmm0, xmm1") == ("fppackedvex", "minps", 0, 0, 1))


def test_decode_vex128_packed_maximum_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vmaxps xmm0, xmm0, xmm1") == ("fppackedvex", "maxps", 0, 0, 1))


def test_decode_vex128_float_xor_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vxorps xmm2, xmm0, xmm1") == ("fppackedvex", "xorps", 2, 0, 1))


def test_decode_vex128_integer_xor_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vpxor xmm2, xmm0, xmm1") == ("fppackedvex", "pxor", 2, 0, 1))


def test_decode_vex128_integer_arithmetic_returns_three_operand_item() -> None:
    expect(_decode_fp_vex_packed_arith("vpaddd xmm2, xmm0, xmm1") == ("fppackedvex", "paddd", 2, 0, 1))


def test_decode_vex128_scalar_arithmetic_preserves_source_one_semantics() -> None:
    expect(_decode_fp_vex_scalar_arith("vaddss xmm2, xmm0, xmm1") == ("fparithvex", "add", 2, 0, 1, 32))
