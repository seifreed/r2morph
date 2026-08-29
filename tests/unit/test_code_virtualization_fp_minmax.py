from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_arith,
    _decode_fp_arith_mem,
)
from tests.utils.assertions import expect


def test_decode_scalar_min_register_preserves_operation_and_width() -> None:
    decoded = _decode_fp_arith("minsd xmm0, xmm1")

    expect(decoded == ("fparith", "min", 0, 1, 64))


def test_decode_scalar_max_memory_preserves_address_form() -> None:
    decoded = _decode_fp_arith_mem("maxss xmm2, dword ptr [rax + 12]")

    expect(decoded == ("fparithmem", "max", 2, 0, 12, 32))
