"""Unit tests for the engine VM's per-build frame-region relocation.

These pin the layout's invariants - the relocatable regions never overlap, they
stay inside the frame's movable window (GP slots below, red zone above), the frame
size is preserved (so the entry signature is stable), and the offsets vary per
build - and confirm the seedless default reserves the scattered GP window.
The end-to-end proof that a relocated frame still computes correctly is carried by
the VM integration suite (which builds with a real frame_seed and checks Unicorn
exit codes across the GP and FP handlers that address every relocated region).
"""

from __future__ import annotations

import itertools

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine_common import GP_REGISTERS, build_vm_scheme
from r2morph.mutations.code_virtualization_engine_frame import (
    _CHECKSUM_SIZE,
    _GP_REGION_END,
    _KEY_DWORD_SIZE,
    _KEY_QWORD_SIZE,
    _RED_ZONE_SIZE,
    _STATE_QWORD_SIZE,
    _VSP_SIZE,
    _VSTACK_SIZE,
    _XMM_SIZE,
    DEFAULT_FRAME_LAYOUT,
    build_frame_layout,
)
from tests.utils.assertions import expect

_FRAME_SIZE = 0x290
_SIZES = {
    "checksum": _CHECKSUM_SIZE,
    "xmm": _XMM_SIZE,
    "vsp": _VSP_SIZE,
    "vstack": _VSTACK_SIZE,
    "keydword": _KEY_DWORD_SIZE,
    "keyqword": _KEY_QWORD_SIZE,
    "stateqword": _STATE_QWORD_SIZE,
}


def _regions(layout) -> list[tuple[int, int]]:
    return sorted(
        [
            (layout.checksum_offset, _CHECKSUM_SIZE),
            (layout.xmm_offset, _XMM_SIZE),
            (layout.vsp_offset, _VSP_SIZE),
            (layout.vstack_base, _VSTACK_SIZE),
            (layout.key_dword_offset, _KEY_DWORD_SIZE),
            (layout.key_qword_offset, _KEY_QWORD_SIZE),
            (layout.state_qword_offset, _STATE_QWORD_SIZE),
        ]
    )


def test_default_layout_reserves_the_scattered_gp_window() -> None:
    expect(
        (
            DEFAULT_FRAME_LAYOUT.frame_size,
            DEFAULT_FRAME_LAYOUT.checksum_offset,
            DEFAULT_FRAME_LAYOUT.xmm_offset,
            DEFAULT_FRAME_LAYOUT.vsp_offset,
            DEFAULT_FRAME_LAYOUT.vstack_base,
            DEFAULT_FRAME_LAYOUT.key_dword_offset,
            DEFAULT_FRAME_LAYOUT.key_qword_offset,
            DEFAULT_FRAME_LAYOUT.state_qword_offset,
        )
        == (656, 160, 176, 432, 440, 472, 480, 496)
    )


def test_scheme_gp_slots_leave_a_hole_in_the_contiguous_context_array() -> None:
    schemes = [build_vm_scheme(randomness.Random(seed)) for seed in range(64)]
    expect(all(set(range(len(GP_REGISTERS))) - set(scheme.slot_perm) for scheme in schemes))


def test_scheme_gp_slots_use_the_reserved_outlier_window() -> None:
    schemes = [build_vm_scheme(randomness.Random(seed)) for seed in range(64)]
    expect(all(any(slot >= len(GP_REGISTERS) for slot in scheme.slot_perm) for scheme in schemes))


def test_relocated_regions_never_overlap_and_stay_in_the_window() -> None:
    for seed in range(1000):
        layout = build_frame_layout(_FRAME_SIZE, randomness.Random(seed))
        expect(layout.frame_size == _FRAME_SIZE)
        regions = _regions(layout)
        expect(not (regions[0][0] < _GP_REGION_END))
        expect(not (regions[-1][0] + regions[-1][1] > _FRAME_SIZE - _RED_ZONE_SIZE))
        for (start, size), (next_start, _) in itertools.pairwise(regions):
            expect(not (start + size > next_start))


def test_layout_varies_across_builds() -> None:
    produced = {
        (
            layout.checksum_offset,
            layout.xmm_offset,
            layout.vsp_offset,
            layout.vstack_base,
            layout.key_dword_offset,
            layout.key_qword_offset,
            layout.state_qword_offset,
        )
        for layout in (build_frame_layout(_FRAME_SIZE, randomness.Random(seed)) for seed in range(64))
    }
    expect(not (len(produced) <= 1))
