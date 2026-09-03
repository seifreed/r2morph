"""Contracts for legacy packed SIMD operations with memory sources."""

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_fp_packed_extra import (
    _decode_fp_packed_arith_extra,
    _decode_fp_packed_arith_extra_idx,
    _decode_fp_packed_arith_extra_mem,
    _decode_fp_packed_arith_extra_riprel,
)
from tests.utils.assertions import expect


def test_decode_extra_packed_memory_operation_uses_direct_address_shape() -> None:
    expect(_decode_fp_packed_arith_extra_mem("pshufb xmm0, [rax + 16]") == ("fppackedmem", "pshufb", 0, 0, 16))


def test_decode_extra_packed_memory_operation_uses_rip_relative_shape() -> None:
    expect(
        _decode_fp_packed_arith_extra_riprel("pmaxub xmm1, [rip + 32]", 0x1000, 7)
        == ("fppackedmemrip", "pmaxub", 1, 0x1027)
    )


def test_classify_extra_packed_memory_operation_uses_indexed_shape() -> None:
    expect(
        _classify({"type": "vec", "opcode": "pcmpeqb xmm2, [rcx*4 + 64]", "addr": 0x1000, "size": 7})
        == ["fppackedmemidxnb", "pcmpeqb", 2, 1, 2, 64]
    )


def test_decode_extra_packed_memory_operation_rejects_register_source() -> None:
    expect(_decode_fp_packed_arith_extra_idx("pcmpgtb xmm0, xmm1") is None)


def test_decode_extra_packed_horizontal_register_operation() -> None:
    expect(_decode_fp_packed_arith_extra("phaddw xmm0, xmm1") == ("fppacked", "phaddw", 0, 1))


def test_classify_extra_packed_horizontal_memory_operation() -> None:
    expect(
        _classify({"type": "vec", "opcode": "phsubd xmm0, [rax + 16]", "addr": 0x1000, "size": 7})
        == ["fppackedmem", "phsubd", 0, 0, 16]
    )
