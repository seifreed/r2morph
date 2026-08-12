"""Unit tests for the engine VM's per-build frame-region relocation.

These pin the layout's invariants - the relocatable regions never overlap, they
stay inside the frame's movable window (GP slots below, red zone above), the frame
size is preserved (so the entry signature is stable), and the offsets vary per
build - and confirm the seedless default reproduces the historical fixed layout.
The end-to-end proof that a relocated frame still computes correctly is carried by
the VM integration suite (which builds with a real frame_seed and checks Unicorn
exit codes across the GP and FP handlers that address every relocated region).
"""

from __future__ import annotations

import itertools
import random

from r2morph.mutations.code_virtualization_engine_frame import (
    _CHECKSUM_SIZE,
    _GP_REGION_END,
    _RED_ZONE_SIZE,
    _VSP_SIZE,
    _VSTACK_SIZE,
    _XMM_SIZE,
    DEFAULT_FRAME_LAYOUT,
    build_frame_layout,
)

_FRAME_SIZE = 0x290
_SIZES = {"checksum": _CHECKSUM_SIZE, "xmm": _XMM_SIZE, "vsp": _VSP_SIZE, "vstack": _VSTACK_SIZE}


def _regions(layout) -> list[tuple[int, int]]:
    return sorted(
        [
            (layout.checksum_offset, _CHECKSUM_SIZE),
            (layout.xmm_offset, _XMM_SIZE),
            (layout.vsp_offset, _VSP_SIZE),
            (layout.vstack_base, _VSTACK_SIZE),
        ]
    )


def test_default_layout_matches_the_historical_fixed_offsets() -> None:
    assert (
        DEFAULT_FRAME_LAYOUT.frame_size,
        DEFAULT_FRAME_LAYOUT.checksum_offset,
        DEFAULT_FRAME_LAYOUT.xmm_offset,
        DEFAULT_FRAME_LAYOUT.vsp_offset,
        DEFAULT_FRAME_LAYOUT.vstack_base,
    ) == (0x290, 0x80, 0x90, 0x190, 0x198)


def test_relocated_regions_never_overlap_and_stay_in_the_window() -> None:
    for seed in range(1000):
        layout = build_frame_layout(_FRAME_SIZE, random.Random(seed))
        assert layout.frame_size == _FRAME_SIZE  # size fixed -> entry signature stable
        regions = _regions(layout)
        assert regions[0][0] >= _GP_REGION_END  # below: GP slots
        assert regions[-1][0] + regions[-1][1] <= _FRAME_SIZE - _RED_ZONE_SIZE  # above: red zone
        for (start, size), (next_start, _) in itertools.pairwise(regions):
            assert start + size <= next_start


def test_layout_varies_across_builds() -> None:
    produced = {
        (layout.checksum_offset, layout.xmm_offset, layout.vsp_offset, layout.vstack_base)
        for layout in (build_frame_layout(_FRAME_SIZE, random.Random(seed)) for seed in range(64))
    }
    assert len(produced) > 1
