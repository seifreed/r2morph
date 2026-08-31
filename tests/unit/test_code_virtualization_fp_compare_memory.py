"""Unit contracts for scalar FP compares against memory."""

from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_fp_decoders import _decode_fp_compare_mem, _decode_fp_compare_riprel
from r2morph.mutations.code_virtualization_region_fp_handlers import _fp_compare_memory_handler_asm
from tests.utils.assertions import expect

_RIPREL_ITEM_SIZE = 6


def test_decode_fp_compare_memory_double_returns_width_and_address() -> None:
    expect(_decode_fp_compare_mem("ucomisd xmm0, qword ptr [rax+8]") == ("fpcmpmem", "ucomisd", 0, 0, 8, 64))


def test_decode_fp_compare_memory_rejects_width_mismatch() -> None:
    expect(_decode_fp_compare_mem("ucomisd xmm0, dword ptr [rax]") is None)


def test_decode_fp_compare_riprel_resolves_target_and_width() -> None:
    expect(
        _decode_fp_compare_riprel("ucomisd xmm1, qword ptr [rip+0x20]", 0x1000, 8)
        == ("fpcmpmemrip", "ucomisd", 1, 0x1028, 64)
    )


def test_decode_fp_compare_riprel_rejects_width_mismatch() -> None:
    expect(_decode_fp_compare_riprel("ucomisd xmm0, dword ptr [rip+0x20]", 0x1000, 8) is None)


def test_encode_fp_compare_riprel_uses_six_byte_memory_item() -> None:
    expect(_item_size(("fpcmpmemrip", "ucomisd", 0, 0x1028, 64)) == _RIPREL_ITEM_SIZE)


def test_fp_compare_riprel_handler_uses_rip_address_prologue() -> None:
    assembly = _fp_compare_memory_handler_asm("fpcmpmemrip_ucomisd_64", "0xAA", "0xAABBCCDD")
    expect("mov r10, r15" in assembly)
