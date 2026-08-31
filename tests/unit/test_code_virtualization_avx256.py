"""Contract tests for the VEX.256 region handler path."""

from __future__ import annotations

import pytest

from r2morph.core import randomness
from r2morph.mutations import code_virtualization_region_classification as classification
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm, build_region_blob
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size, encode_region
from r2morph.mutations.code_virtualization_region_fp_handlers import _fp_packed_vex_arith_handler_asm
from r2morph.mutations.code_virtualization_region_models import Region, RegionScheme, _op_key
from r2morph.mutations.code_virtualization_region_nesting import _nested_xmm_state_asm
from tests.utils.assertions import expect

_CAVE_VADDR = 0x500000
_EXIT_VADDR = 0x2000
_VEX_PACKED_REGISTER_ITEM_SIZE = 4


def _vex_256_region() -> Region:
    items = [("fppackedvex256", "addps", 0, 1, 2), ("exit", _EXIT_VADDR)]
    op_keys = {_op_key(item) for item in items}
    return Region(items, _EXIT_VADDR, 0x1000, {key for key in op_keys if key is not None}, [(0x1000, 5)])


def test_vex_256_region_assembly_uses_ymm_handler() -> None:
    region = _vex_256_region()
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(7)))

    expect("vaddps ymm0, ymm0, ymm1" in assembly)


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
