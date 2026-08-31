"""Contract tests for the VEX.256 region handler path."""

from __future__ import annotations

import pytest

from r2morph.core import randomness
from r2morph.mutations import code_virtualization_region_classification as classification
from r2morph.mutations.code_virtualization_engine_common import _FP_PACKED_VEX_OPERATIONS
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm, build_region_blob
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size, encode_region
from r2morph.mutations.code_virtualization_region_fp_decoders import (
    _decode_fp_compare,
    _decode_fp_vex_256_lane_permute_immediate,
    _decode_fp_vex_256_packed_arith,
    _decode_fp_vex_256_permute_immediate,
    _decode_fp_vex_256_variable_blend,
    _decode_fp_vex_256_variable_permute,
    _decode_fp_vex_packed_compare,
    _decode_fp_vex_packed_compare_mem,
)
from r2morph.mutations.code_virtualization_region_fp_handlers import (
    VexMemoryHandlerConfig,
    _fp_packed_vex_arith_handler_asm,
    _fp_vex_256_permute_immediate_handler_asm,
    _fp_vex_256_permute_lane_immediate_handler_asm,
    _fp_vex_256_variable_blend_handler_asm,
    _fp_vex_256_variable_permute_handler_asm,
    _fp_vex_packed_compare_handler_asm,
    _fp_vex_packed_compare_memory_handler_asm,
)
from r2morph.mutations.code_virtualization_region_models import Region, RegionScheme, _op_key
from r2morph.mutations.code_virtualization_region_nesting import _nested_xmm_state_asm
from tests.utils.assertions import expect

_CAVE_VADDR = 0x500000
_EXIT_VADDR = 0x2000
_VEX_PACKED_REGISTER_ITEM_SIZE = 4
_VEX_PACKED_COMPARE_ITEM_SIZE = 5
_VEX_256_PERMUTE_ITEM_SIZE = 5
_VEX_256_PERMUTE_IMMEDIATE = 0x31
_VEX_256_LANE_PERMUTE_ITEM_SIZE = 4
_VEX_256_LANE_PERMUTE_IMMEDIATE = 0x1B
_VEX_256_VARIABLE_BLEND_ITEM_SIZE = 5
_VEX_256_VARIABLE_PERMUTE_ITEM_SIZE = 4


def _vex_256_region() -> Region:
    items = [("fppackedvex256", "addps", 0, 1, 2), ("exit", _EXIT_VADDR)]
    op_keys = {_op_key(item) for item in items}
    return Region(items, _EXIT_VADDR, 0x1000, {key for key in op_keys if key is not None}, [(0x1000, 5)])


def test_vex_256_region_assembly_uses_ymm_handler() -> None:
    region = _vex_256_region()
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(7)))

    expect("vaddps ymm0, ymm0, ymm1" in assembly)


def test_vex_256_addsub_float_assembly_uses_native_instruction() -> None:
    items = [("fppackedvex256", "addsubps", 0, 1, 2), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items}, [(0x1000, 5)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(9)))

    expect("vaddsubps ymm0, ymm0, ymm1" in assembly)


def test_vex_256_addsub_double_decoder_preserves_sources() -> None:
    decoded = _decode_fp_vex_256_packed_arith("vaddsubpd ymm0, ymm1, ymm2")

    expect(decoded == ("fppackedvex256", "addsubpd", 0, 1, 2))


def test_vex_256_byte_compare_decoder_preserves_sources() -> None:
    decoded = _decode_fp_vex_256_packed_arith("vpcmpeqb ymm0, ymm1, ymm2")

    expect(decoded == ("fppackedvex256", "pcmpeqb", 0, 1, 2))


def test_vex_256_qword_compare_decoder_preserves_sources() -> None:
    decoded = _decode_fp_vex_256_packed_arith("vpcmpeqq ymm0, ymm1, ymm2")

    expect(decoded == ("fppackedvex256", "pcmpeqq", 0, 1, 2))


def test_vex_128_compare_operations_have_engine_handlers() -> None:
    expected = {"vpcmpeqb", "vpcmpeqw", "vpcmpeqq", "vpcmpgtb", "vpcmpgtw", "vpcmpgtq"}

    expect(expected.issubset(set(_FP_PACKED_VEX_OPERATIONS)))


def test_vex_256_word_compare_assembly_uses_native_instruction() -> None:
    items = [("fppackedvex256", "pcmpgtw", 0, 1, 2), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items}, [(0x1000, 5)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(10)))

    expect("vpcmpgtw ymm0, ymm0, ymm1" in assembly)


def test_vex_256_test_assembly_uses_native_instruction() -> None:
    items = [("fpcmpvex256", "vptest", 0, 1), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items}, [(0x1000, 5)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(11)))

    expect(_decode_fp_compare("vptest ymm0, ymm1") == ("fpcmpvex256", "vptest", 0, 1))
    expect("vptest ymm0, ymm1" in assembly)


def test_vex128_float_test_assembly_uses_native_instruction() -> None:
    items = [("fpcmp", "vtestps", 0, 1), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items}, [(0x1000, 3)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(13)))

    expect("vtestps xmm0, xmm1" in assembly)


def test_vex256_double_test_assembly_uses_native_instruction() -> None:
    items = [("fpcmpvex256", "vtestpd", 0, 1), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items}, [(0x1000, 3)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(14)))

    expect("vtestpd ymm0, ymm1" in assembly)


def test_vex_packed_float_compare_decoder_preserves_xmm_operands_and_predicate() -> None:
    decoded = _decode_fp_vex_packed_compare("vcmpps xmm0, xmm1, xmm2, 0")

    expect(decoded == ("fppackedvexcmp", "vcmpps", 0, 1, 2, 0))


def test_vex256_packed_double_compare_decoder_preserves_ymm_operands_and_predicate() -> None:
    decoded = _decode_fp_vex_packed_compare("vcmppd ymm0, ymm1, ymm2, 14")

    expect(decoded == ("fppackedvex256cmp", "vcmppd", 0, 1, 2, 14))


def test_vex256_packed_compare_memory_decoder_preserves_base_and_predicate() -> None:
    decoded = _decode_fp_vex_packed_compare_mem("vcmpps ymm0, ymm1, ymmword ptr [rax + 32], 0", 0x1000, 8)

    expect(decoded == ("fppackedvex256cmpmem", "vcmpps", 0, 1, 0, 32, 0))


def test_vex128_packed_compare_memory_decoder_preserves_indexed_address() -> None:
    decoded = _decode_fp_vex_packed_compare_mem("vcmppd xmm2, xmm3, xmmword ptr [rcx*8 + 64], 14", 0x1000, 8)

    expect(decoded == ("fppackedvexcmpmemidxnb", "vcmppd", 2, 3, 1, 3, 64, 14))


def test_vex256_packed_compare_memory_classification_preserves_operands() -> None:
    classified = classification._classify(
        {"type": "compare", "opcode": "vcmpps ymm0, ymm1, ymmword ptr [rax + 32], 0", "addr": 0x1000, "size": 8}
    )

    expect(classified == ["fppackedvex256cmpmem", "vcmpps", 0, 1, 0, 32, 0])


def test_vex_packed_compare_memory_item_sizes_include_predicate() -> None:
    sizes = (
        _item_size(("fppackedvexcmpmem", "vcmpps", 0, 1, 0, 32, 0)),
        _item_size(("fppackedvexcmpmemrip", "vcmppd", 0, 1, 0x1000, 14)),
        _item_size(("fppackedvex256cmpmemidx", "vcmpps", 0, 1, 0, 2, 1, 32, 0)),
        _item_size(("fppackedvex256cmpmemidxnb", "vcmppd", 0, 1, 2, 1, 32, 14)),
    )

    expect(sizes == (9, 8, 11, 10))


def test_vex256_packed_compare_memory_handler_loads_memory_source() -> None:
    items = [("fppackedvex256cmpmem", "vcmpps", 0, 1, 2, 32, 0), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items}, [(0x1000, 9)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(15)))

    expect("vmovups ymm1, [" in assembly and "vcmpps ymm0, ymm0, ymm1, 0" in assembly)


def test_vex128_packed_compare_memory_handler_clears_upper_state() -> None:
    assembly = _fp_vex_packed_compare_memory_handler_asm(
        "fppackedvexcmpmem_vcmpps_0", "0xAA", "0xAABBCCDD", VexMemoryHandlerConfig(preserve_ymm=True)
    )

    expect("vcmpps xmm0, xmm0, xmm1, 0" in assembly and "movups [rsp + r8 + 768], xmm2" in assembly)


def test_vex256_packed_float_compare_assembly_uses_native_instruction() -> None:
    items = [("fppackedvex256cmp", "vcmpps", 0, 1, 2, 0), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items}, [(0x1000, 5)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(12)))

    expect(_item_size(items[0]) == _VEX_PACKED_COMPARE_ITEM_SIZE)
    expect("vcmpps ymm0, ymm0, ymm1, 0" in assembly)


def test_vex_packed_float_compare_handler_clears_vex128_upper_state() -> None:
    assembly = _fp_vex_packed_compare_handler_asm("fppackedvexcmp_vcmpps_0", "0xAA", preserve_ymm=True)

    expect("vcmpps xmm0, xmm0, xmm1, 0" in assembly and "movups [rsp + r8 + 768], xmm2" in assembly)


def test_vex_256_variable_shift_assembly_uses_ymm_handler() -> None:
    items = [("fppackedvex256", "pslld", 0, 1, 2), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items}, [(0x1000, 5)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(8)))

    expect("vpslld ymm0, ymm0, ymm1" in assembly)


def test_vex_256_packed_arithmetic_item_accounts_for_three_operand_fields() -> None:
    expect(_item_size(("fppackedvex256", "pslld", 0, 1, 2)) == _VEX_PACKED_REGISTER_ITEM_SIZE)


def test_vex_256_immediate_shift_assembly_uses_native_immediate() -> None:
    items = [("fppackedvex256imm", "psrad", 0, 1, 7), ("exit", _EXIT_VADDR)]
    op_keys = {_op_key(item) for item in items}
    region = Region(items, _EXIT_VADDR, 0x1000, {key for key in op_keys if key is not None}, [(0x1000, 5)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(17)))

    expect("vpsrad ymm0, ymm0, 7" in assembly)


def test_vex_256_immediate_shuffle_assembly_uses_native_immediate() -> None:
    items = [("fppackedvex256imm", "pshufd", 0, 1, 0x1B), ("exit", _EXIT_VADDR)]
    op_keys = {_op_key(item) for item in items}
    region = Region(items, _EXIT_VADDR, 0x1000, {key for key in op_keys if key is not None}, [(0x1000, 6)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(18)))

    expect("vpshufd ymm0, ymm0, 27" in assembly)


def test_vex_256_lane_permutation_decoder_preserves_registers_and_immediate() -> None:
    decoded = _decode_fp_vex_256_permute_immediate("vperm2f128 ymm0, ymm1, ymm2, 0x31")

    expect(decoded == ("fppackedvex256permimm", "perm2f128", 0, 1, 2, _VEX_256_PERMUTE_IMMEDIATE))


def test_vex_256_lane_permutation_handler_uses_native_instruction() -> None:
    assembly = _fp_vex_256_permute_immediate_handler_asm("fppackedvex256permimm_perm2f128_49", "0xAA")

    expect("vperm2f128 ymm0, ymm0, ymm1, 49" in assembly)


def test_vex_256_float_shuffle_decoder_preserves_sources_and_immediate() -> None:
    decoded = _decode_fp_vex_256_permute_immediate("vshufps ymm0, ymm1, ymm2, 0x1B")

    expect(decoded == ("fppackedvex256permimm", "shufps", 0, 1, 2, 0x1B))


def test_vex_256_float_shuffle_handler_uses_native_instruction() -> None:
    assembly = _fp_vex_256_permute_immediate_handler_asm("fppackedvex256permimm_shufps_27", "0xAA")

    expect("vshufps ymm0, ymm0, ymm1, 27" in assembly)


def test_vex_256_double_shuffle_decoder_preserves_sources_and_immediate() -> None:
    decoded = _decode_fp_vex_256_permute_immediate("vshufpd ymm0, ymm1, ymm2, 0x05")

    expect(decoded == ("fppackedvex256permimm", "shufpd", 0, 1, 2, 5))


def test_vex_256_double_shuffle_handler_uses_native_instruction() -> None:
    assembly = _fp_vex_256_permute_immediate_handler_asm("fppackedvex256permimm_shufpd_5", "0xAA")

    expect("vshufpd ymm0, ymm0, ymm1, 5" in assembly)


def test_vex_256_float_blend_decoder_preserves_sources_and_immediate() -> None:
    decoded = _decode_fp_vex_256_permute_immediate("vblendps ymm0, ymm1, ymm2, 0x5A")

    expect(decoded == ("fppackedvex256permimm", "blendps", 0, 1, 2, 0x5A))


def test_vex_256_float_blend_handler_uses_native_instruction() -> None:
    assembly = _fp_vex_256_permute_immediate_handler_asm("fppackedvex256permimm_blendps_90", "0xAA")

    expect("vblendps ymm0, ymm0, ymm1, 90" in assembly)


def test_vex_256_double_blend_decoder_preserves_sources_and_immediate() -> None:
    decoded = _decode_fp_vex_256_permute_immediate("vblendpd ymm0, ymm1, ymm2, 0x5")

    expect(decoded == ("fppackedvex256permimm", "blendpd", 0, 1, 2, 5))


def test_vex_256_double_blend_handler_uses_native_instruction() -> None:
    assembly = _fp_vex_256_permute_immediate_handler_asm("fppackedvex256permimm_blendpd_5", "0xAA")

    expect("vblendpd ymm0, ymm0, ymm1, 5" in assembly)


def test_vex_256_variable_blend_decoder_preserves_mask_register() -> None:
    decoded = _decode_fp_vex_256_variable_blend("vblendvps ymm0, ymm1, ymm2, ymm3")

    expect(decoded == ("fppackedvex256var", "blendvps", 0, 1, 2, 3))


def test_vex_256_variable_double_blend_decoder_preserves_mask_register() -> None:
    decoded = _decode_fp_vex_256_variable_blend("vblendvpd ymm4, ymm5, ymm6, ymm7")

    expect(decoded == ("fppackedvex256var", "blendvpd", 4, 5, 6, 7))


def test_vex_256_variable_blend_handler_uses_native_mask_register() -> None:
    assembly = _fp_vex_256_variable_blend_handler_asm("fppackedvex256var_blendvps", "0xAA")

    expect("vblendvps ymm0, ymm0, ymm1, ymm2" in assembly)


def test_vex_256_variable_blend_item_accounts_for_four_register_fields() -> None:
    expect(_item_size(("fppackedvex256var", "blendvps", 0, 1, 2, 3)) == _VEX_256_VARIABLE_BLEND_ITEM_SIZE)


def test_vex_256_variable_blend_classification_preserves_all_operands() -> None:
    classified = classification._classify(
        {"type": "blend", "opcode": "vblendvps ymm0, ymm1, ymm2, ymm3", "addr": 0x1000, "size": 5}
    )

    expect(classified == ["fppackedvex256var", "blendvps", 0, 1, 2, 3])


def test_vex_256_variable_permute_decoder_preserves_control_register() -> None:
    decoded = _decode_fp_vex_256_variable_permute("vpermilps ymm0, ymm1, ymm2")

    expect(decoded == ("fppackedvex256varpermil", "permilps", 0, 1, 2))


def test_vex_256_variable_double_permute_decoder_preserves_control_register() -> None:
    decoded = _decode_fp_vex_256_variable_permute("vpermilpd ymm4, ymm5, ymm6")

    expect(decoded == ("fppackedvex256varpermil", "permilpd", 4, 5, 6))


def test_vex_256_variable_permute_handler_uses_native_instruction() -> None:
    assembly = _fp_vex_256_variable_permute_handler_asm("fppackedvex256varpermil_permilps", "0xAA")

    expect("vpermilps ymm0, ymm0, ymm1" in assembly)


def test_vex_256_variable_permute_item_accounts_for_three_register_fields() -> None:
    expect(_item_size(("fppackedvex256varpermil", "permilps", 0, 1, 2)) == _VEX_256_VARIABLE_PERMUTE_ITEM_SIZE)


def test_vex_256_variable_permute_classification_preserves_all_operands() -> None:
    classified = classification._classify(
        {"type": "vec", "opcode": "vpermilps ymm0, ymm1, ymm2", "addr": 0x1000, "size": 5}
    )

    expect(classified == ["fppackedvex256varpermil", "permilps", 0, 1, 2])


def test_vex_256_lane_permutation_item_includes_immediate_byte() -> None:
    expect(
        _item_size(("fppackedvex256permimm", "perm2f128", 0, 1, 2, _VEX_256_PERMUTE_IMMEDIATE))
        == _VEX_256_PERMUTE_ITEM_SIZE
    )


def test_vex_256_lane_shuffle_decoder_preserves_register_and_immediate() -> None:
    decoded = _decode_fp_vex_256_lane_permute_immediate("vpermilps ymm0, ymm1, 0x1B")

    expect(
        decoded
        == (
            "fppackedvex256permilimm",
            "permilps",
            0,
            1,
            _VEX_256_LANE_PERMUTE_IMMEDIATE,
        )
    )


def test_vex_256_lane_shuffle_handler_uses_native_instruction() -> None:
    assembly = _fp_vex_256_permute_lane_immediate_handler_asm("fppackedvex256permilimm_permilps_27", "0xAA")

    expect("vpermilps ymm0, ymm0, 27" in assembly)


def test_vex_256_double_lane_shuffle_decoder_preserves_register_and_immediate() -> None:
    decoded = _decode_fp_vex_256_lane_permute_immediate("vpermilpd ymm0, ymm1, 0x05")

    expect(decoded == ("fppackedvex256permilimm", "permilpd", 0, 1, 5))


def test_vex_256_double_lane_shuffle_handler_uses_native_instruction() -> None:
    assembly = _fp_vex_256_permute_lane_immediate_handler_asm("fppackedvex256permilimm_permilpd_5", "0xAA")

    expect("vpermilpd ymm0, ymm0, 5" in assembly)


def test_vex_256_lane_shuffle_item_uses_pair_stride() -> None:
    expect(
        _item_size(
            (
                "fppackedvex256permilimm",
                "permilps",
                0,
                1,
                _VEX_256_LANE_PERMUTE_IMMEDIATE,
            )
        )
        == _VEX_256_LANE_PERMUTE_ITEM_SIZE
    )


def test_vex_256_immediate_shuffle_encoding_keeps_branch_offsets_aligned() -> None:
    items = [
        ("fppackedvex256imm", "pshufd", 0, 1, 0x1B),
        ("jmp", 2),
        ("exit", _EXIT_VADDR),
    ]
    op_keys = {_op_key(item) for item in items}
    scheme = RegionScheme(
        {
            "fppackedvex256imm_pshufd_27": (7,),
            "jmp": (8,),
            f"exit_{_EXIT_VADDR}": (9,),
        },
        0,
        1,
        tuple(range(17)),
        1,
    )
    region = Region(items, _EXIT_VADDR, 0x1000, {key for key in op_keys if key is not None}, [(0x1000, 6)])

    encoded = encode_region(region, scheme, 0x2000)

    expect(encoded == bytes((7, 0, 1, 0x1B, 0x0C, 13, 4, 4, 4, 0)))


def test_vex128_packed_handler_commits_zeroed_ymm_upper_slot() -> None:
    assembly = _fp_packed_vex_arith_handler_asm("fppackedvex_paddd", "0xAA", preserve_ymm=True)

    expect("pxor xmm2, xmm2" in assembly and "[rsp + r8 + 768]" in assembly)


def test_vex128_packed_handler_without_ymm_state_stays_inside_frame() -> None:
    assembly = _fp_packed_vex_arith_handler_asm("fppackedvex_paddd", "0xAA")

    expect("[rsp + r8 + 768]" not in assembly)


def test_vex_256_region_builds_a_real_blob() -> None:
    region = _vex_256_region()
    scheme = build_region_scheme(region, randomness.Random(7))

    expect(build_region_blob(region, _CAVE_VADDR, scheme) is not None)


def test_nested_vex_256_state_preserves_upper_halves() -> None:
    region = _vex_256_region()
    region.instructions.append(("call", 0x2000))

    spill, reload = _nested_xmm_state_asm(region, [region])

    expect("vextractf128 xmm0, ymm0, 1" in spill and "vinsertf128 ymm0, ymm0, xmmword ptr [rsp + 768], 1" in reload)


def test_vex_256_memory_move_classification_preserves_address_shape() -> None:
    load = classification._classify(
        {"type": "mov", "opcode": "vmovups ymm0, ymmword ptr [rax + 32]", "addr": 0x1000, "size": 7}
    )

    expect(load == ["fploadvex256", 0, 0, 32])


def test_vex_256_memory_move_classification_supports_rip_and_indexed_forms() -> None:
    rip = classification._classify(
        {"type": "mov", "opcode": "vmovups ymmword ptr [rip + 16], ymm1", "addr": 0x1000, "size": 7}
    )
    indexed = classification._classify(
        {"type": "mov", "opcode": "vmovups ymm2, ymmword ptr [rax + rcx*4 + 64]", "addr": 0x1000, "size": 7}
    )
    no_base = classification._classify(
        {"type": "mov", "opcode": "vmovups ymmword ptr [rcx*4 + 64], ymm2", "addr": 0x1000, "size": 7}
    )

    expect(
        rip == ["fpstorevex256rip", 1, 0x1000 + 7 + 16]
        and indexed == ["fploadvex256idx", 2, 0, 1, 2, 64]
        and no_base == ["fpstorevex256idxnb", 2, 1, 2, 64]
    )


def test_vex_256_memory_arithmetic_classification_supports_base_form() -> None:
    arithmetic = classification._classify(
        {"type": "add", "opcode": "vaddps ymm0, ymm1, ymmword ptr [rax + 32]", "addr": 0x1000, "size": 8}
    )

    expect(arithmetic == ["fppackedvex256mem", "addps", 0, 1, 0, 32])


def test_vex_256_memory_unary_classification_supports_sqrt() -> None:
    arithmetic = classification._classify(
        {"type": "sqrt", "opcode": "vsqrtps ymm0, ymmword ptr [rax + 32]", "addr": 0x1000, "size": 8}
    )

    expect(arithmetic == ["fppackedvex256mem", "sqrtps", 0, 0, 0, 32])


def test_vex_256_memory_arithmetic_classification_supports_rip_form() -> None:
    arithmetic = classification._classify(
        {"type": "add", "opcode": "vaddps ymm0, ymm1, ymmword ptr [rip + 16]", "addr": 0x1000, "size": 8}
    )

    expect(arithmetic == ["fppackedvex256memrip", "addps", 0, 1, 0x1000 + 8 + 16])


def test_vex_256_memory_arithmetic_classification_supports_indexed_forms() -> None:
    indexed = classification._classify(
        {"type": "add", "opcode": "vaddps ymm2, ymm3, ymmword ptr [rax + rcx*4 + 64]", "addr": 0x1000, "size": 8}
    )
    no_base = classification._classify(
        {"type": "add", "opcode": "vaddps ymm2, ymm3, ymmword ptr [rcx*4 + 64]", "addr": 0x1000, "size": 8}
    )

    expect(
        indexed == ["fppackedvex256memidx", "addps", 2, 3, 0, 1, 2, 64]
        and no_base == ["fppackedvex256memidxnb", "addps", 2, 3, 1, 2, 64]
    )


def test_vex_256_memory_arithmetic_handler_loads_memory_source() -> None:
    items = [("fppackedvex256mem", "addps", 0, 1, 2, 32), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items if _op_key(item)}, [(0x1000, 8)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(11)))

    expect("vmovups ymm1, [r10]" in assembly and "vaddps ymm0, ymm0, ymm1" in assembly)


def test_vex_256_memory_arithmetic_encoding_keeps_ymm_indices_logical() -> None:
    region = Region(
        [("fppackedvex256mem", "addps", 0, 1, 2, 32)],
        _EXIT_VADDR,
        0x1000,
        {"fppackedvex256mem_addps"},
        [(0x1000, 8)],
    )
    scheme = RegionScheme(
        {"fppackedvex256mem_addps": (7,)},
        0,
        1,
        tuple(reversed(range(17))),
        1,
    )

    encoded = encode_region(region, scheme, 0x1000)

    expect(encoded == bytes((7, 0, 14, 32, 0, 0, 0, 1)))


def test_vex_256_memory_unary_handler_uses_unary_instruction() -> None:
    items = [("fppackedvex256mem", "sqrtps", 0, 0, 2, 32), ("exit", _EXIT_VADDR)]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items if _op_key(item)}, [(0x1000, 8)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(12)))

    expect("vsqrtps ymm0, ymm1" in assembly)


def test_vex_256_memory_move_handlers_use_ymm_width() -> None:
    items = [
        ("fploadvex256", 0, 1, 0),
        ("fpstorevex256", 0, 1, 32),
        ("exit", _EXIT_VADDR),
    ]
    region = Region(items, _EXIT_VADDR, 0x1000, {_op_key(item) for item in items if _op_key(item)}, [(0x1000, 10)])
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(9)))

    expect("vmovups ymm0, [r10]" in assembly and "vmovups [r10], ymm0" in assembly)


@pytest.mark.parametrize(
    "item",
    [
        ("fploadvex256", 0, 1, 0),
        ("fpstorevex256rip", 0, 0x1010),
        ("fploadvex256idx", 0, 1, 2, 1, 8),
        ("fpstorevex256idxnb", 0, 2, 1, 8),
    ],
)
def test_vex_256_memory_move_encoding_uses_ymm_layout(item: tuple[object, ...]) -> None:
    region = Region(
        [item],
        _EXIT_VADDR,
        0x1000,
        {_op_key(item)},
        [(0x1000, 7)],
    )

    expect(isinstance(encode_region(region, build_region_scheme(region, randomness.Random(13)), 0x2000), bytes))
