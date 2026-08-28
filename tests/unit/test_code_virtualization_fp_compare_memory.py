"""Unit contracts for scalar FP compares against memory."""

from r2morph.mutations.code_virtualization_region_fp_decoders import _decode_fp_compare_mem
from tests.utils.assertions import expect


def test_decode_fp_compare_memory_double_returns_width_and_address() -> None:
    expect(_decode_fp_compare_mem("ucomisd xmm0, qword ptr [rax+8]") == ("fpcmpmem", "ucomisd", 0, 0, 8, 64))


def test_decode_fp_compare_memory_rejects_width_mismatch() -> None:
    expect(_decode_fp_compare_mem("ucomisd xmm0, dword ptr [rax]") is None)
