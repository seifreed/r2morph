from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_arith,
    _decode_fp_arith_mem,
    _decode_fp_packed_arith,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import _fp_vex_scalar_arith_handler_asm
from tests.utils.assertions import expect


def test_decode_scalar_sqrt_register_preserves_operation_and_width() -> None:
    decoded = _decode_fp_arith("sqrtsd xmm0, xmm1")

    expect(decoded == ("fparith", "sqrt", 0, 1, 64))


def test_decode_scalar_sqrt_memory_preserves_address_form() -> None:
    decoded = _decode_fp_arith_mem("sqrtss xmm2, dword ptr [rax + 12]")

    expect(decoded == ("fparithmem", "sqrt", 2, 0, 12, 32))


def test_decode_packed_sqrt_register_preserves_instruction() -> None:
    decoded = _decode_fp_packed_arith("sqrtpd xmm3, xmm4")

    expect(decoded == ("fppacked", "sqrtpd", 3, 4))


def test_vex_scalar_sqrt_handler_merges_source_one_lanes() -> None:
    assembly = _fp_vex_scalar_arith_handler_asm("fparithvex_sqrt_32", "0xAA")

    expect("sqrtss xmm1, xmm1" in assembly and "movss xmm0, xmm1" in assembly)
