"""Contract tests for the VEX.256 region handler path."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm, build_region_blob
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
from r2morph.mutations.code_virtualization_region_nesting import _nested_xmm_state_asm
from tests.utils.assertions import expect

_CAVE_VADDR = 0x500000
_EXIT_VADDR = 0x2000


def _vex_256_region() -> Region:
    items = [("fppackedvex256", "addps", 0, 1, 2), ("exit", _EXIT_VADDR)]
    op_keys = {_op_key(item) for item in items}
    return Region(items, _EXIT_VADDR, 0x1000, {key for key in op_keys if key is not None}, [(0x1000, 5)])


def test_vex_256_region_assembly_uses_ymm_handler() -> None:
    region = _vex_256_region()
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(7)))

    expect("vaddps ymm0, ymm0, ymm1" in assembly)


def test_vex_256_region_builds_a_real_blob() -> None:
    region = _vex_256_region()
    scheme = build_region_scheme(region, randomness.Random(7))

    expect(build_region_blob(region, _CAVE_VADDR, scheme) is not None)


def test_nested_vex_256_state_preserves_upper_halves() -> None:
    region = _vex_256_region()
    region.instructions.append(("call", 0x2000))

    spill, reload = _nested_xmm_state_asm(region, [region])

    expect("vextractf128 xmm0, ymm0, 1" in spill and "vinsertf128 ymm0, ymm0, xmm0, 1" in reload)
