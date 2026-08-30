"""Contracts for VEX.128 arithmetic and scalar moves with memory operands."""

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_vex_packed_arith_mem,
    _decode_fp_vex_scalar_arith_mem,
    _decode_fp_vex_scalar_move,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import (
    VexMemoryHandlerConfig,
    _fp_vex_packed_arith_mem_handler_asm,
    _fp_vex_scalar_arith_mem_handler_asm,
    _fp_vex_scalar_memory_move_handler_asm,
    _fp_vex_scalar_merge_handler_asm,
    _fp_vex_scalar_move_handler_asm,
)
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
from tests.utils.assertions import expect

_VEX128_MEMORY_ITEM_SIZE = 8


def test_decode_vex128_packed_memory_arithmetic_preserves_base_shape() -> None:
    item = _decode_fp_vex_packed_arith_mem("vaddps xmm0, xmm1, xmmword ptr [rax + 32]", 0x1000, 8)

    expect(item == ("fppackedvexmem", "addps", 0, 1, 0, 32))


def test_decode_vex128_scalar_memory_arithmetic_preserves_base_shape() -> None:
    item = _decode_fp_vex_scalar_arith_mem("vaddss xmm0, xmm1, dword ptr [rax + 32]", 0x1000, 8)

    expect(item == ("fparithvexmem", "add", 0, 1, 0, 32, 32))


def test_decode_vex128_scalar_memory_arithmetic_preserves_indexed_shapes() -> None:
    indexed = _decode_fp_vex_scalar_arith_mem("vaddsd xmm2, xmm3, qword ptr [rax + rcx*4 + 64]", 0x1000, 8)
    no_base = _decode_fp_vex_scalar_arith_mem("vaddsd xmm2, xmm3, qword ptr [rcx*4 + 64]", 0x1000, 8)

    expect(
        indexed == ("fparithvexmemidx", "add", 2, 3, 0, 1, 2, 64, 64)
        and no_base == ("fparithvexmemidxnb", "add", 2, 3, 1, 2, 64, 64)
    )


def test_decode_vex128_scalar_moves_preserves_zero_and_merge_forms() -> None:
    register = _decode_fp_vex_scalar_move("vmovss xmm0, xmm1", 0x1000, 4)
    merge = _decode_fp_vex_scalar_move("vmovsd xmm2, xmm3, xmm4", 0x1000, 5)
    load = _decode_fp_vex_scalar_move("vmovss xmm5, dword ptr [rax + 8]", 0x1000, 5)
    store = _decode_fp_vex_scalar_move("vmovsd qword ptr [rax + rcx*8 + 16], xmm5", 0x1000, 6)

    expect(
        register == ("fpmovvexscalar", 32, 0, 1)
        and merge == ("fpmovvexscalar3", 64, 2, 3, 4)
        and load == ("fploadvex", 5, 0, 8, 32)
        and store == ("fpstorevexidx", 5, 0, 1, 3, 16, 64)
    )


def test_decode_vex128_packed_memory_arithmetic_supports_rip_relative_shape() -> None:
    item = _decode_fp_vex_packed_arith_mem("vaddps xmm0, xmm1, xmmword ptr [rip + 16]", 0x1000, 8)

    expect(item == ("fppackedvexmemrip", "addps", 0, 1, 0x1018))


def test_decode_vex128_packed_memory_arithmetic_supports_no_base_index_shape() -> None:
    item = _decode_fp_vex_packed_arith_mem("vaddps xmm2, xmm3, xmmword ptr [rcx*4 + 64]", 0x1000, 8)

    expect(item == ("fppackedvexmemidxnb", "addps", 2, 3, 1, 2, 64))


def test_decode_vex128_packed_memory_arithmetic_supports_based_index_shape() -> None:
    item = _decode_fp_vex_packed_arith_mem("vaddps xmm2, xmm3, xmmword ptr [rax + rcx*4 + 64]", 0x1000, 8)

    expect(item == ("fppackedvexmemidx", "addps", 2, 3, 0, 1, 2, 64))


def test_classify_vex128_packed_memory_unary_operation_uses_destination_as_source() -> None:
    item = _classify(
        {"type": "vec", "family": "vec", "opcode": "vsqrtps xmm0, xmmword ptr [rax]", "addr": 0x1000, "size": 7}
    )

    expect(item == ["fppackedvexmem", "sqrtps", 0, 0, 0, 0])


def test_vex128_packed_memory_item_has_address_shape_and_clears_ymm_upper_state() -> None:
    item = ("fppackedvexmem", "addps", 0, 1, 2, 32)
    assembly = _fp_vex_packed_arith_mem_handler_asm(
        "fppackedvexmem_addps",
        "0xAA",
        "0x01010101",
        VexMemoryHandlerConfig(preserve_ymm=True),
    )

    expect(
        _op_key(item) == "fppackedvexmem_addps"
        and _item_size(item) == _VEX128_MEMORY_ITEM_SIZE
        and "pxor xmm2, xmm2" in assembly
    )


def test_vex128_region_spills_ymm_upper_state_for_existing_vex_arithmetic() -> None:
    region = Region(
        [("fppackedvex", "addps", 0, 1, 2), ("exit", 0x2000)],
        0x2000,
        0x1000,
        {"fppackedvex_addps", "exit_8192"},
        [(0x1000, 5)],
    )

    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(3)))

    expect("[rsp + r8 + 768]" in assembly)


def test_vex128_scalar_memory_handler_preserves_source_lanes_and_clears_upper_state() -> None:
    assembly = _fp_vex_scalar_arith_mem_handler_asm(
        "fparithvexmem_add_32",
        "0xAA",
        "0x01010101",
        VexMemoryHandlerConfig(preserve_ymm=True),
    )

    expect(
        "movups xmm0, [rsp + r11 + 256]" in assembly
        and "vaddss xmm0, xmm0, dword ptr [r10]" in assembly
        and "pxor xmm2, xmm2" in assembly
    )


def test_vex128_scalar_move_handlers_preserve_vex_zero_and_merge_semantics() -> None:
    move = _fp_vex_scalar_move_handler_asm("fpmovvexscalar_32", "0xAA", preserve_ymm=True)
    merge = _fp_vex_scalar_merge_handler_asm("fpmovvexscalar3_32", "0xAA", preserve_ymm=True)
    memory = _fp_vex_scalar_memory_move_handler_asm(
        "fpmovvexmem_32",
        "0xAA",
        "0x01010101",
        VexMemoryHandlerConfig(preserve_ymm=True),
    )

    expect(
        "vmovss xmm0, xmm0" in move
        and "vmovss xmm0, xmm0, xmm1" in merge
        and "vmovss xmm0, xmm0, dword ptr [r10]" in memory
    )
