"""Per-build frame-layout relocation for the engine VM.

Besides the 16 scattered GP register slots, the interpreter's private frame holds a
self-checksum byte, the xmm save area, and the micro-op virtual operand stack.
Placing those at fixed offsets every build hands a devirtualizer a stable map of
the VM's internal state - the checksum slot in particular is a named signature.
This module packs the three at per-build-randomized offsets (order permuted, with
jitter) inside the movable middle of the frame, while keeping three things fixed:
the frame *size* (so the ``sub rsp, N`` entry signature is stable), the GP
candidate window at the base (their register->slot selection is ``slot_perm``'s job), and the
System V red zone pinned at the top so a leaf callee's red-zone data survives.

The layout is self-consistent by construction: every offset the interpreter emits
comes from one :class:`FrameLayout`, so relocating a region moves all of its
references together and the encoder (which folds only the checksum *value*, never
a slot offset) is untouched.
"""

from __future__ import annotations

from dataclasses import dataclass

import r2morph.core.randomness as random

# GP register slots are selected from [0, _GP_REGION_END); the System V red zone is
# pinned to the top _RED_ZONE_SIZE bytes. The relocatable regions live between.
_GP_REGION_END = 0xA0
_RED_ZONE_SIZE = 0x80

# Byte budgets for the relocatable regions. The checksum needs one byte but takes
# a qword cell for alignment; the xmm save area is 16 slots of 16 bytes; the vsp
# is a single pointer word; the micro-op stack's peak depth is two cells (each
# arithmetic op pushes at most two and pops back to empty), so four is ample.
_CHECKSUM_SIZE = 0x8
_XMM_SIZE = 0x100
_VSP_SIZE = 0x8
_VSTACK_SIZE = 0x20
# The operand-cipher key's 32/64-bit self-checksum broadcasts, each a qword cell,
# precomputed once at entry so handlers decrypt operands against the runtime
# checksum rather than a build constant.
_KEY_DWORD_SIZE = 0x8
_KEY_QWORD_SIZE = 0x8


@dataclass(frozen=True)
class FrameLayout:
    """Byte offsets of the interpreter's frame regions for one build."""

    frame_size: int
    checksum_offset: int
    xmm_offset: int
    vsp_offset: int
    vstack_base: int
    key_dword_offset: int
    key_qword_offset: int


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
        ("keydword", _KEY_DWORD_SIZE),
        ("keyqword", _KEY_QWORD_SIZE),
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
    return FrameLayout(
        frame_size,
        offsets["checksum"],
        offsets["xmm"],
        offsets["vsp"],
        offsets["vstack"],
        offsets["keydword"],
        offsets["keyqword"],
    )


# The canonical fixed layout, used when a build carries no frame seed.
DEFAULT_FRAME_LAYOUT = FrameLayout(
    frame_size=0x290,
    checksum_offset=0xA0,
    xmm_offset=0xB0,
    vsp_offset=0x1B0,
    vstack_base=0x1B8,
    key_dword_offset=0x1D8,
    key_qword_offset=0x1E0,
)
