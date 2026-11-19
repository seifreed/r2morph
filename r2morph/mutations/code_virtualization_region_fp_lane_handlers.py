"""Assembly handlers for VEX.128 lane transfers."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_layout import pair_offsets, triple_offsets
from r2morph.mutations.code_virtualization_region_fp_handlers import _clear_ymm_upper_slot_asm
from r2morph.mutations.code_virtualization_region_handlers import _XMM_SAVE_OFFSET

_LANE_WIDTH_BYTES = 16
_BYTE_WIDTH_BITS = 8
_WORD_WIDTH_BITS = 16
_DWORD_WIDTH_BITS = 32
_QWORD_WIDTH_BITS = 64
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


def _fp_vex_gp_extract_handler_asm(handler_key: str, key: str, field_perm: int = 0) -> str:
    """Extract one packed dword or qword from an XMM save slot into a GP slot."""
    _, width_text, immediate_text = handler_key.split("_")
    width = int(width_text)
    immediate = int(immediate_text)
    instruction = {
        _BYTE_WIDTH_BITS: "vpextrb",
        _WORD_WIDTH_BITS: "vpextrw",
        _DWORD_WIDTH_BITS: "vpextrd",
        _QWORD_WIDTH_BITS: "vpextrq",
    }[width]
    offsets = pair_offsets("xmm", "gp", field_perm)
    return (
        f"  movzx r8d, byte ptr [rsi+{offsets['xmm']}]\n"
        f"  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{offsets['gp']}]\n"
        f"  xor r9b, {key}\n  xor r9b, r13b\n"
        "  movzx r10d, byte ptr [rsi+3]\n"
        f"  xor r10b, {key}\n  xor r10b, r13b\n"
        "  shl r8, 4\n"
        f"  movups xmm0, [rsp + r8 + {_XMM_SAVE_OFFSET}]\n"
        f"  {instruction} {'rax' if width == _QWORD_WIDTH_BITS else 'eax'}, xmm0, {immediate}\n"
        "  mov qword ptr [rsp + r9*8], rax\n"
        "  add rsi, 4\n  jmp vm_dispatch\n"
    )


def _fp_vex_gp_insert_handler_asm(
    handler_key: str,
    key: str,
    field_perm: int = 0,
    preserve_ymm: bool = False,
) -> str:
    """Insert a GP dword into an XMM lane and clear the VEX upper half."""
    immediate = int(handler_key.rsplit("_", 1)[1])
    offsets = triple_offsets("dst", "src", "gp", field_perm)
    decode = "".join(
        f"  movzx {reg}d, byte ptr [rsi+{offsets[field]}]\n  xor {reg}b, {key}\n  xor {reg}b, r13b\n"
        for reg, field in (("r8", "dst"), ("r9", "src"), ("r10", "gp"))
    )
    clear_upper = _clear_ymm_upper_slot_asm("r8") if preserve_ymm else ""
    return (
        decode
        + "  shl r8, 4\n  shl r9, 4\n"
        + f"  movups xmm0, [rsp + r9 + {_XMM_SAVE_OFFSET}]\n"
        + "  mov eax, dword ptr [rsp + r10*8]\n"
        + f"  vpinsrd xmm0, xmm0, eax, {immediate}\n"
        + f"  movups [rsp + r8 + {_XMM_SAVE_OFFSET}], xmm0\n"
        + clear_upper
        + "  add rsi, 4\n  jmp vm_dispatch\n"
    )
