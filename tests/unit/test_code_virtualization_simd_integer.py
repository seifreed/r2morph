"""Unit contracts for integer packed XMM operations."""

from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_compare,
    _decode_fp_packed_arith,
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


def test_decode_packed_test_returns_flag_compare_item() -> None:
    expect(_decode_fp_compare("ptest xmm0, xmm1") == ("fpcmp", "ptest", 0, 1))
