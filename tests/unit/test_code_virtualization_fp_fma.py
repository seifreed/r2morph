"""Unit contracts for packed VEX FMA lowering."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_fp_fma import (
    _decode_fp_vex_fma,
    _fp_vex_fma_handler_asm,
)
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
from tests.utils.assertions import expect

_VEX_REGISTER_ITEM_SIZE = 4


def test_decode_vex_fma_preserves_xmm_operand_order() -> None:
    item = _decode_fp_vex_fma("vfmadd231ps xmm0, xmm1, xmm2")

    expect(item == ("fppackedvex", "vfmadd231ps", 0, 1, 2))


def test_decode_vex_fma_preserves_ymm_operand_order() -> None:
    item = _decode_fp_vex_fma("vfnmsub132pd ymm3, ymm4, ymm5")

    expect(item == ("fppackedvex256", "vfnmsub132pd", 3, 4, 5))


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
