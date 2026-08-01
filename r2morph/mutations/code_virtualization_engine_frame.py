"""Per-build frame-layout relocation for the engine VM.

Besides the 16 GP register slots, the interpreter's private frame holds a
self-checksum byte, the xmm save area, and the micro-op virtual operand stack.
Placing those at fixed offsets every build hands a devirtualizer a stable map of
the VM's internal state - the checksum slot in particular is a named signature.
This module packs the three at per-build-randomized offsets (order permuted, with
jitter) inside the movable middle of the frame, while keeping three things fixed:
the frame *size* (so the ``sub rsp, N`` entry signature is stable), the 16 GP
slots at the base (their register->slot shuffling is ``slot_perm``'s job), and the
System V red zone pinned at the top so a leaf callee's red-zone data survives.

The layout is self-consistent by construction: every offset the interpreter emits
comes from one :class:`FrameLayout`, so relocating a region moves all of its
references together and the encoder (which folds only the checksum *value*, never
a slot offset) is untouched.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

# The 16 GP register slots occupy [0, _GP_REGION_END); the System V red zone is
# pinned to the top _RED_ZONE_SIZE bytes. The relocatable regions live between.
_GP_REGION_END = 0x80
_RED_ZONE_SIZE = 0x80

# Byte budgets for the relocatable regions. The checksum needs one byte but takes
# a qword cell for alignment; the xmm save area is 16 slots of 16 bytes; the vsp
# is a single pointer word; the micro-op stack's peak depth is two cells (each
# arithmetic op pushes at most two and pops back to empty), so eight is ample.
_CHECKSUM_SIZE = 0x8
_XMM_SIZE = 0x100
_VSP_SIZE = 0x8
_VSTACK_SIZE = 0x40


@dataclass(frozen=True)
class FrameLayout:
    """Byte offsets of the interpreter's frame regions for one build."""

    frame_size: int
    checksum_offset: int
    xmm_offset: int
    vsp_offset: int
    vstack_base: int


def build_frame_layout(frame_size: int, rng: random.Random) -> FrameLayout:
    """Pack the relocatable regions at randomized offsets in the frame's middle.

    The regions are laid out in a per-build-shuffled order, each preceded by a
    random gap drawn from the remaining slack, so both their order and their exact
    offsets vary between builds. Raises if the movable window cannot hold them.
    """
    window_start = _GP_REGION_END
    window_end = frame_size - _RED_ZONE_SIZE
    regions = [
        ("checksum", _CHECKSUM_SIZE),
        ("xmm", _XMM_SIZE),
        ("vsp", _VSP_SIZE),
        ("vstack", _VSTACK_SIZE),
    ]
    rng.shuffle(regions)
    slack = window_end - window_start - sum(size for _, size in regions)
    if slack < 0:
        raise ValueError(f"frame window [{window_start:#x}, {window_end:#x}) too small for the VM regions")
    offsets: dict[str, int] = {}
    cursor = window_start
    for name, size in regions:
        gap = rng.randint(0, slack)
        cursor += gap
        slack -= gap
        offsets[name] = cursor
        cursor += size
    return FrameLayout(frame_size, offsets["checksum"], offsets["xmm"], offsets["vsp"], offsets["vstack"])


# The canonical fixed layout, used when a build carries no frame seed (frame_seed
# 0) so existing behaviour is reproduced byte-for-byte.
DEFAULT_FRAME_LAYOUT = FrameLayout(
    frame_size=0x290,
    checksum_offset=0x80,
    xmm_offset=0x90,
    vsp_offset=0x190,
    vstack_base=0x198,
)
