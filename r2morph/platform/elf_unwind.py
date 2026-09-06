"""Build compact ELF unwind metadata for a complete VM region."""

from __future__ import annotations

import struct

_DW_EH_PE_PCREL_SDATA4 = 0x1B
_DW_EH_PE_DATAREL_SDATA4 = 0x3B
_PT_GNU_EH_FRAME = 0x6474E550
_DW_CFA_ADVANCE_LOC1 = 0x02
_DW_CFA_ADVANCE_LOC2 = 0x03
_DW_CFA_ADVANCE_LOC4 = 0x04
_DW_CFA_DEF_CFA = 0x0C
_DW_CFA_DEF_CFA_OFFSET = 0x0E
_DW_CFA_OFFSET_RIP = 0x90
_X86_64_RSP = 7
_X86_64_RIP = 16
_SUB_RSP_IMMEDIATE_BYTES = 7
_EH_FRAME_HEADER_SIZE = 20
_MAX_U32 = (1 << 32) - 1
_MIN_S32 = -(1 << 31)
_MAX_S32 = (1 << 31) - 1
_MAX_U8 = 0xFF
_MAX_U16 = 0xFFFF


def _uleb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def _sleb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        encoded.append(byte | (0x80 if not done else 0))
        if done:
            return bytes(encoded)


def _sdata4(value: int) -> bytes:
    if not _MIN_S32 <= value <= _MAX_S32:
        raise ValueError(f"relative unwind pointer is outside signed 32-bit range: {value}")
    return struct.pack("<i", value)


def _cie() -> bytes:
    instructions = bytes(
        (
            _DW_CFA_DEF_CFA,
            _X86_64_RSP,
            8,
            _DW_CFA_OFFSET_RIP,
            1,
        )
    )
    body = b"\x00\x01zR\x00" + _uleb128(1) + _sleb128(-8) + _uleb128(_X86_64_RIP) + b"\x01\x1b" + instructions
    return struct.pack("<I", len(body)) + body


def _advance_loc(delta: int) -> bytes:
    if delta < 0:
        raise ValueError("unwind location delta cannot be negative")
    if delta <= _MAX_U8:
        return bytes((_DW_CFA_ADVANCE_LOC1, delta))
    if delta <= _MAX_U16:
        return bytes((_DW_CFA_ADVANCE_LOC2,)) + struct.pack("<H", delta)
    if delta <= _MAX_U32:
        return bytes((_DW_CFA_ADVANCE_LOC4,)) + struct.pack("<I", delta)
    raise ValueError("unwind location delta exceeds 32-bit range")


def _def_cfa_offset(offset: int) -> bytes:
    if offset <= 0 or offset > _MAX_U32:
        raise ValueError("CFA offset is outside the supported range")
    return bytes((_DW_CFA_DEF_CFA_OFFSET,)) + _uleb128(offset)


def _fde(
    eh_frame_vaddr: int,
    blob_vaddr: int,
    blob_size: int,
    frame_size: int,
    call_ranges: tuple[tuple[int, int, int], ...],
) -> bytes:
    cie = _cie()
    fde_vaddr = eh_frame_vaddr + len(cie)
    content_start = fde_vaddr + 4
    cie_pointer = content_start - eh_frame_vaddr
    instructions = _advance_loc(_SUB_RSP_IMMEDIATE_BYTES) + _def_cfa_offset(frame_size + 8)
    current_offset = _SUB_RSP_IMMEDIATE_BYTES
    for start_offset, end_offset, cfa_offset in sorted(call_ranges):
        if not current_offset <= start_offset < end_offset <= blob_size:
            raise ValueError("call unwind range is outside the VM blob")
        instructions += _advance_loc(start_offset - current_offset) + _def_cfa_offset(cfa_offset)
        instructions += _advance_loc(end_offset - start_offset) + _def_cfa_offset(frame_size + 8)
        current_offset = end_offset
    body = (
        struct.pack("<I", cie_pointer)
        + _sdata4(blob_vaddr - (fde_vaddr + 8))
        + struct.pack("<I", blob_size)
        + b"\x00"
        + instructions
    )
    fde = struct.pack("<I", len(body)) + body
    return cie + fde + b"\x00\x00\x00\x00"


def build_vm_eh_frame(
    blob_vaddr: int,
    blob_size: int,
    frame_size: int,
    metadata_vaddr: int,
    call_ranges: tuple[tuple[int, int, int], ...] = (),
) -> bytes:
    """Build one searchable FDE for a VM blob that starts at function entry.

    The blob changes only ``rsp`` in its prologue, spills/restores registers, and
    returns to the native continuation. The FDE therefore describes the caller
    return address before the prologue and the VM frame after its seven-byte
    ``sub rsp, immediate`` instruction. ``call_ranges`` contains
    ``(start, end, cfa_offset)`` offsets for bridges whose hardware stack is
    temporarily relocated. LSDA-bearing call sites remain outside this contract.
    """
    if blob_vaddr < 0 or blob_size <= 0 or blob_size > _MAX_U32:
        raise ValueError("VM unwind metadata requires a non-empty 32-bit blob range")
    if frame_size <= 0 or frame_size > _MAX_U32 - 8:
        raise ValueError("VM unwind metadata requires a positive 32-bit frame size")

    eh_frame_vaddr = metadata_vaddr + _EH_FRAME_HEADER_SIZE
    eh_frame = _fde(eh_frame_vaddr, blob_vaddr, blob_size, frame_size, call_ranges)
    fde_vaddr = eh_frame_vaddr + len(_cie())
    header = (
        bytes((1, _DW_EH_PE_PCREL_SDATA4, 0x03, _DW_EH_PE_DATAREL_SDATA4))
        + _sdata4(eh_frame_vaddr - (metadata_vaddr + 4))
        + struct.pack("<I", 1)
        + _sdata4(blob_vaddr - metadata_vaddr)
        + _sdata4(fde_vaddr - metadata_vaddr)
    )
    if len(header) != _EH_FRAME_HEADER_SIZE:
        raise ValueError("unexpected .eh_frame_hdr size")
    return header + eh_frame


__all__ = ["_PT_GNU_EH_FRAME", "build_vm_eh_frame"]
