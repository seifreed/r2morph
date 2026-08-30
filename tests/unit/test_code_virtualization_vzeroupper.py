"""Contract tests for the VZEROUPPER region handler."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations import code_virtualization_region_classification as classification
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import _interpreter_asm, build_region_blob
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_fp_handlers import vzeroupper_handler_asm
from r2morph.mutations.code_virtualization_region_models import Region, _op_key
from tests.utils.assertions import expect

_CAVE_VADDR = 0x500000
_EXIT_VADDR = 0x2000


def _vzeroupper_region() -> Region:
    items = [("vzeroupper",), ("exit", _EXIT_VADDR)]
    op_keys = {key for item in items if (key := _op_key(item)) is not None}
    return Region(items, _EXIT_VADDR, 0x1000, op_keys, [(0x1000, 3)])


def test_classify_vzeroupper_yields_state_clear_item() -> None:
    expect(classification._classify({"type": "vec", "opcode": "vzeroupper"}) == ["vzeroupper"])


def test_vzeroupper_item_encodes_as_single_opcode_byte() -> None:
    expect(_item_size(("vzeroupper",)) == 1)


def test_vzeroupper_handler_clears_saved_upper_halves() -> None:
    assembly = vzeroupper_handler_asm()

    expect("pxor xmm0, xmm0" in assembly and "[rsp + 768]" in assembly and "[rsp + 1008]" in assembly)


def test_vzeroupper_region_uses_ymm_state() -> None:
    region = _vzeroupper_region()
    assembly = _interpreter_asm(region, build_region_scheme(region, randomness.Random(7)))

    expect("pxor xmm0, xmm0" in assembly and "vextractf128 xmm0, ymm0, 1" in assembly)


def test_vzeroupper_region_builds_a_real_blob() -> None:
    region = _vzeroupper_region()
    scheme = build_region_scheme(region, randomness.Random(7))

    expect(build_region_blob(region, _CAVE_VADDR, scheme) is not None)
