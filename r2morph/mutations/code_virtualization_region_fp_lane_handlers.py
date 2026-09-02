"""Assembly handler for VEX.128 lane extraction."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_layout import pair_offsets
from r2morph.mutations.code_virtualization_region_handlers import _XMM_SAVE_OFFSET

_LANE_WIDTH_BYTES = 16
_YMM_UPPER_SAVE_OFFSET = 0x300


def _fp_vex_lane_extract_handler_asm(
    handler_key: str, key: str, field_perm: int = 0, _preserve_ymm: bool = False
) -> str:
    """Copy one 128-bit YMM lane and clear the VEX.128 destination upper half."""
    _, lane_text = handler_key.split("_", 1)
    if not lane_text.startswith("extract"):
        raise ValueError(f"invalid VEX lane handler key: {handler_key}")
    lane = int(lane_text.removeprefix("extract"))
    if lane not in (0, 1):
        raise ValueError(f"invalid VEX lane: {lane}")

    offsets = pair_offsets("dst", "src", field_perm)
    source_offset = _XMM_SAVE_OFFSET if lane == 0 else _YMM_UPPER_SAVE_OFFSET
    return (
        f"  movzx r8d, byte ptr [rsi+{offsets['dst']}]\n"
        f"  xor r8b, {key}\n"
        "  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{offsets['src']}]\n"
        f"  xor r9b, {key}\n"
        "  xor r9b, r13b\n"
        f"  shl r8, {_LANE_WIDTH_BYTES.bit_length() - 1}\n"
        f"  shl r9, {_LANE_WIDTH_BYTES.bit_length() - 1}\n"
        f"  movups xmm0, [rsp + r9 + {source_offset}]\n"
        f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        "  pxor xmm1, xmm1\n"
        f"  movups [rsp + r8 + {_YMM_UPPER_SAVE_OFFSET}], xmm1\n"
        "  add rsi, 3\n"
        "  jmp vm_dispatch\n"
    )
