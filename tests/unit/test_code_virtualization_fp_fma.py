"""Unit contracts for packed VEX FMA lowering."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_fp_fma import (
    _decode_fp_vex_256_fma_mem,
    _decode_fp_vex_fma,
    _decode_fp_vex_fma_mem,
    _decode_fp_vex_scalar_fma,
    _decode_fp_vex_scalar_fma_mem,
    _fp_vex_fma_handler_asm,
    _fp_vex_fma_memory_handler_asm,
    _fp_vex_scalar_fma_handler_asm,
    _fp_vex_scalar_fma_memory_handler_asm,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import VexMemoryHandlerConfig
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
from tests.utils.assertions import expect

_VEX_REGISTER_ITEM_SIZE = 4


def test_decode_vex_fma_preserves_xmm_operand_order() -> None:
    item = _decode_fp_vex_fma("vfmadd231ps xmm0, xmm1, xmm2")

    expect(item == ("fppackedvex", "vfmadd231ps", 0, 1, 2))


def test_decode_vex_fma_preserves_ymm_operand_order() -> None:
    item = _decode_fp_vex_fma("vfnmsub132pd ymm3, ymm4, ymm5")

    expect(item == ("fppackedvex256", "vfnmsub132pd", 3, 4, 5))


def test_decode_vex_fma_memory_preserves_source_and_address_shape() -> None:
    xmm = _decode_fp_vex_fma_mem("vfmadd231ps xmm0, xmm1, xmmword ptr [rax + 32]", 0x1000, 8)
    ymm = _decode_fp_vex_256_fma_mem("vfnmsub132pd ymm3, ymm4, ymmword ptr [rcx*4 + 64]", 0x1000, 8)

    expect(
        xmm == ("fppackedvexmem", "vfmadd231ps", 0, 1, 0, 32)
        and ymm == ("fppackedvex256memidxnb", "vfnmsub132pd", 3, 4, 1, 2, 64)
    )


def test_decode_vex_scalar_fma_preserves_form_and_width() -> None:
    single = _decode_fp_vex_scalar_fma("vfmadd132ss xmm0, xmm1, xmm2")
    double = _decode_fp_vex_scalar_fma("vfnmsub231sd xmm3, xmm4, xmm5")

    expect(
        single == ("fparithvex", "vfmadd132ss", 0, 1, 2, 32) and double == ("fparithvex", "vfnmsub231sd", 3, 4, 5, 64)
    )


def test_decode_vex_scalar_fma_memory_preserves_address_shape() -> None:
    item = _decode_fp_vex_scalar_fma_mem("vfmadd213sd xmm2, xmm3, qword ptr [rax + rcx*4 + 64]", 0x1000, 8)

    expect(item == ("fparithvexmemidx", "vfmadd213sd", 2, 3, 0, 1, 2, 64, 64))


def test_classify_vex_fma_uses_existing_three_register_bytecode_shape() -> None:
    item = _classify(
        {"type": "vec", "family": "vec", "opcode": "vfmadd213pd xmm0, xmm1, xmm2", "addr": 0x1000, "size": 5}
    )

    expect(item == ["fppackedvex", "vfmadd213pd", 0, 1, 2])


def test_vex_fma_handlers_emit_native_width_and_operand_order() -> None:
    xmm = _fp_vex_fma_handler_asm("fppackedvex_vfmadd231ps", "0xAA", preserve_ymm=True)
    ymm = _fp_vex_fma_handler_asm("fppackedvex256_vfnmsub132pd", "0xAA")

    expect(
        "vfmadd231ps xmm0, xmm1, xmm2" in xmm and "vfnmsub132pd ymm0, ymm1, ymm2" in ymm and "pxor xmm2, xmm2" in xmm
    )


def test_vex_fma_item_is_encoded_and_routed() -> None:
    item = ("fppackedvex256", "vfmadd231ps", 0, 1, 2)
    region = Region(
        [item, ("exit", 0x2000)],
        0x2000,
        0x1000,
        {_op_key(item), "exit_8192"},
        [(0x1000, 5)],
    )

    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(5)))

    expect(_item_size(item) == _VEX_REGISTER_ITEM_SIZE and "vfmadd231ps ymm0, ymm1, ymm2" in assembly)


def test_vex_fma_memory_handler_uses_memory_as_third_source() -> None:
    assembly = _fp_vex_fma_memory_handler_asm(
        "fppackedvex256mem_vfmadd231ps", "0xAA", "0xAABBCCDD", VexMemoryHandlerConfig(preserve_ymm=True)
    )

    expect("vfmadd231ps ymm0, ymm1, ymmword ptr [r10]" in assembly and "add rsi, 8" in assembly)


def test_vex_scalar_fma_handlers_preserve_native_form() -> None:
    register = _fp_vex_scalar_fma_handler_asm("fparithvex_vfnmsub132ss_32", "0xAA", preserve_ymm=True)
    memory = _fp_vex_scalar_fma_memory_handler_asm(
        "fparithvexmem_vfmadd231sd_64", "0xAA", "0xAABBCCDD", VexMemoryHandlerConfig(preserve_ymm=True)
    )

    expect(
        "vfnmsub132ss xmm0, xmm1, xmm2" in register
        and "vfmadd231sd xmm0, xmm1, qword ptr [r10]" in memory
        and "add rsi, 8" in memory
    )
