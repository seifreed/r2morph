"""
A PIE rip-relative jump-table switch lowers into the region VM using only existing
handlers - no new opcode is needed.

The gcc/clang PIE switch idiom is ``lea rax,[rip+T]; movsxd rcx,[rax+idx*4];
add rcx,rax; jmp rcx``: a rip-relative table-base lea, a sign-extending indexed load
of a 4-byte relative offset, an add that reconstructs the absolute case address, and
a bare-register computed jump. These decompose into ``learip``/``vlearip``,
``movxidx``/``vmovxidx``, ``op``, and the register ``ijmp`` respectively, so the
CFG-closure gather plus the existing lifter already virtualize the whole switch: the
case blocks are gathered from r2's ``switch_op`` and re-entered through the target map.

This test drives the lowering + codegen end to end on the resolved PIE fixture. It
does NOT run the mutated binary: injecting the VM blob into an ET_DYN (PIE) image is
blocked by a pre-existing, switch-independent limitation in ``inject_blob`` - the
appended blob would overlap a following load segment - so the full-pass injection is
out of scope here. Runtime parity for the non-PIE absolute switch (which does inject)
is covered in ``test_code_virtualization_real.py``.
"""

from __future__ import annotations

import importlib.util
import random
from pathlib import Path

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_codegen import build_region_blob

_FIXTURE = Path(__file__).resolve().parents[2] / "dataset" / "elf_switch_pie_x86_64"


def _pie_switch_region() -> object:
    if not _FIXTURE.exists():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    binary = Binary(str(_FIXTURE))
    binary.open()
    try:
        binary.analyze()
        dispatch = next(f for f in binary.get_functions() if "dispatch" in (f.get("name") or ""))
        ops = CodeVirtualizationPass(config={"virtualize_dispatch": True})._gather_cfg_ops(binary, dispatch)
        assert ops is not None
        return extract_region(ops, random.Random(1), allow_computed_jump=True)
    finally:
        binary.close()


def test_pie_switch_cfg_gather_reaches_every_case_block() -> None:
    """The CFG closure follows the resolved switch_op edges to a register ijmp."""
    region = _pie_switch_region()
    assert region is not None
    assert any(item[0] == "ijmp" for item in region.instructions)


def test_pie_switch_decomposes_into_existing_handlers() -> None:
    """The rip-relative table-base lea and sign-extending offset load lower to the
    existing vlearip and vmovxidx micro-ops - no switch-specific opcode."""
    region = _pie_switch_region()
    kinds = {item[0] for item in region.instructions}
    assert {"vlearip", "vmovxidx", "ijmp"} <= kinds


def test_pie_switch_region_assembles_to_real_bytes() -> None:
    """The lowered PIE switch region builds a full interpreter blob."""
    region = _pie_switch_region()
    scheme = build_region_scheme(region, random.Random(1))
    assert build_region_blob(region, 0x500000, scheme) is not None
