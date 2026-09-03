"""Contracts for VEX packed unsigned word saturation with memory sources."""

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_vex_256_packed_arith_mem,
    _decode_fp_vex_packed_arith_mem,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import _fp_vex_256_packed_arith_mem_handler_asm
from tests.utils.assertions import expect


def test_decode_vpackusdw_vex128_memory_preserves_operation_and_address() -> None:
    item = _decode_fp_vex_packed_arith_mem("vpackusdw xmm0, xmm1, xmmword ptr [rax + 32]", 0x1000, 8)

    expect(item == ("fppackedvexmem", "packusdw", 0, 1, 0, 32))


def test_decode_vpackusdw_vex256_memory_preserves_operation_and_address() -> None:
    item = _decode_fp_vex_256_packed_arith_mem("vpackusdw ymm0, ymm1, ymmword ptr [rax + 32]", 0x1000, 8)

    expect(item == ("fppackedvex256mem", "packusdw", 0, 1, 0, 32))


def test_classify_vpackusdw_vex256_memory_routes_to_packed_handler() -> None:
    item = _classify(
        {
            "type": "vec",
            "family": "vec",
            "opcode": "vpackusdw ymm0, ymm1, ymmword ptr [rax + 32]",
            "addr": 0x1000,
            "size": 8,
        }
    )

    expect(item == ["fppackedvex256mem", "packusdw", 0, 1, 0, 32])


def test_vpackusdw_vex256_memory_handler_emits_native_operation() -> None:
    assembly = _fp_vex_256_packed_arith_mem_handler_asm("fppackedvex256mem_packusdw", "0xAA", "0xAABBCCDD")

    expect("vpackusdw ymm0, ymm0, ymm1" in assembly)
