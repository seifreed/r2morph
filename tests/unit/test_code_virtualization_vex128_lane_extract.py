"""Unit contracts for VEX.128 lane extraction virtualization."""

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_fp_extra_decoders import (
    _decode_fp_vex_convert,
    _decode_fp_vex_lane_extract,
)
from r2morph.mutations.code_virtualization_region_fp_lane_handlers import _fp_vex_lane_extract_handler_asm
from r2morph.mutations.code_virtualization_region_models import _op_key
from tests.utils.assertions import expect

_VEX128_ITEM_SIZE = 3


def test_decode_vex128_lane_extract_preserves_lane_and_registers() -> None:
    expect(_decode_fp_vex_lane_extract("vextractf128 xmm6, ymm5, 1") == ("fpmovvex", "extract1", 6, 5))


def test_decode_vex128_integer_lane_extract_uses_bitwise_move_contract() -> None:
    expect(_decode_fp_vex_lane_extract("vextracti128 xmm2, ymm7, 0") == ("fpmovvex", "extract0", 2, 7))


def test_decode_vex_scalar_conversion_reuses_integer_conversion_contract() -> None:
    expect(_decode_fp_vex_convert("vcvttss2si eax, xmm4") == ("cvtf2i", 32, 32, 0, 4))


def test_classify_vex128_lane_extract_routes_to_vex_move_shape() -> None:
    instruction = {
        "type": "vec",
        "family": "vec",
        "opcode": "vextractf128 xmm6, ymm5, 1",
        "addr": 0x1000,
        "size": 6,
    }
    expect(_classify(instruction) == ["fpmovvex", "extract1", 6, 5])


def test_classify_vex_scalar_conversion_routes_to_conversion_shape() -> None:
    instruction = {"type": "null", "family": "cpu", "opcode": "vcvttss2si eax, xmm4", "addr": 0x1200, "size": 4}
    expect(_classify(instruction) == ["cvtf2i", 32, 32, 0, 4])


def test_vex128_lane_extract_uses_existing_three_byte_item_encoding() -> None:
    item = ("fpmovvex", "extract1", 6, 5)
    expect(_item_size(item) == _VEX128_ITEM_SIZE)


def test_vex128_lane_extract_key_keeps_lane_specific_handler_identity() -> None:
    expect(_op_key(("fpmovvex", "extract1", 6, 5)) == "fpmovvex_extract1")


def test_vex128_lane_extract_handler_reads_upper_lane_and_clears_destination_upper() -> None:
    assembly = _fp_vex_lane_extract_handler_asm("fpmovvex_extract1", "0xAA")
    expect(
        "movups xmm0, [rsp + r9 + 768]" in assembly
        and "movups [rsp + r8 + 256], xmm0" in assembly
        and "movups [rsp + r8 + 768], xmm1" in assembly
    )
