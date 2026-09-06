"""Build compact ELF unwind metadata for a complete VM region."""

from __future__ import annotations

import struct
from dataclasses import dataclass

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
_DW_EH_PE_OMIT = 0xFF
_DW_EH_PE_SDATA4 = 0x0B
_DW_EH_PE_PCREL_SDATA4 = 0x1B


@dataclass(frozen=True)
class VmEhFrameSpec:
    """Inputs for an injected VM FDE and its optional remapped LSDA."""

    blob_vaddr: int
    blob_size: int
    frame_size: int
    metadata_vaddr: int
    call_ranges: tuple[tuple[int, int, int], ...] = ()
    lsda_template: tuple[int, int, int | None, int, bytes] | None = None
    lsda_call_sites: tuple[tuple[int, int, int, int], ...] = ()
    personality: int | None = None


@dataclass(frozen=True)
class _FdeSpec:
    eh_frame_vaddr: int
    blob_vaddr: int
    blob_size: int
    frame_size: int
    call_ranges: tuple[tuple[int, int, int], ...]
    cie: bytes
    lsda_vaddr: int | None = None


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
    body = (
        b"\x00\x00\x00\x00\x01zR\x00" + _uleb128(1) + _sleb128(-8) + _uleb128(_X86_64_RIP) + b"\x01\x1b" + instructions
    )
    return struct.pack("<I", len(body)) + body


def _cie_with_personality(eh_frame_vaddr: int, personality: int) -> bytes:
    """Build a CIE carrying the original language personality routine."""
    prefix = b"\x00\x00\x00\x00\x01zPLR\x00\x01\x78\x10"
    augmentation = b"\x07\x1b" + _sdata4(personality - (eh_frame_vaddr + 4 + len(prefix) + 2)) + b"\x1b\x1b"
    instructions = bytes((_DW_CFA_DEF_CFA, _X86_64_RSP, 8, _DW_CFA_OFFSET_RIP, 1))
    body = prefix + augmentation + instructions
    return struct.pack("<I", len(body)) + body


def _build_lsda(
    blob_vaddr: int,
    blob_size: int,
    template: tuple[int, int, int | None, int, bytes],
    call_sites: tuple[tuple[int, int, int, int], ...],
    lsda_vaddr: int,
) -> bytes:
    """Rebuild only the LSDA call-site table and retain action/type bytes."""
    _landing_pad_encoding, type_encoding, type_table_offset, action_table_offset, suffix = template
    if type_encoding != _DW_EH_PE_OMIT and type_table_offset is None:
        raise ValueError("LSDA type encoding has no type-table offset")
    if type_table_offset is not None and type_table_offset < action_table_offset:
        raise ValueError("LSDA type-table offset precedes the action table")

    entries = bytearray()
    for start, end, landing_pad, action_index in call_sites:
        if not blob_vaddr <= start < end <= blob_vaddr + blob_size:
            raise ValueError("LSDA call-site range is outside the VM blob")
        for value in (start - blob_vaddr, end - start, landing_pad - blob_vaddr):
            entries.extend(_sdata4(value))
        entries.extend(_uleb128(action_index))

    action_delta = 0 if type_table_offset is None else type_table_offset - action_table_offset
    if action_delta < 0:
        raise ValueError("LSDA type-table offset precedes the action table")
    landing_pad_base = blob_vaddr
    call_site_table = bytes((_DW_EH_PE_SDATA4,)) + _uleb128(len(entries)) + entries
    header = bytes((_DW_EH_PE_PCREL_SDATA4,)) + _sdata4(landing_pad_base - (lsda_vaddr + 1))
    header += bytes((type_encoding,))
    if type_table_offset is None:
        return header + call_site_table + suffix
    type_offset_size = 1
    for _ in range(4):
        type_offset = len(header) + type_offset_size + len(call_site_table) + action_delta
        encoded_type_offset = _uleb128(type_offset)
        if len(encoded_type_offset) == type_offset_size:
            return header + encoded_type_offset + call_site_table + suffix
        type_offset_size = len(encoded_type_offset)
    raise ValueError("LSDA type-table offset did not converge")


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


def _fde(spec: _FdeSpec) -> bytes:
    fde_vaddr = spec.eh_frame_vaddr + len(spec.cie)
    content_start = fde_vaddr + 4
    cie_pointer = content_start - spec.eh_frame_vaddr
    instructions = _advance_loc(_SUB_RSP_IMMEDIATE_BYTES) + _def_cfa_offset(spec.frame_size + 8)
    current_offset = _SUB_RSP_IMMEDIATE_BYTES
    for start_offset, end_offset, cfa_offset in sorted(spec.call_ranges):
        if not current_offset <= start_offset < end_offset <= spec.blob_size:
            raise ValueError("call unwind range is outside the VM blob")
        instructions += _advance_loc(start_offset - current_offset) + _def_cfa_offset(cfa_offset)
        instructions += _advance_loc(end_offset - start_offset) + _def_cfa_offset(spec.frame_size + 8)
        current_offset = end_offset
    augmentation = b"\x00"
    if spec.lsda_vaddr is not None:
        augmentation_field = fde_vaddr + 4 + 4 + 4 + 4 + 1
        augmentation = b"\x04" + _sdata4(spec.lsda_vaddr - augmentation_field)
    body = struct.pack("<I", cie_pointer) + _sdata4(spec.blob_vaddr - (fde_vaddr + 8))
    body += struct.pack("<I", spec.blob_size)
    body += augmentation + instructions
    fde = struct.pack("<I", len(body)) + body
    return spec.cie + fde + b"\x00\x00\x00\x00"


def _build_vm_eh_frame(spec: VmEhFrameSpec) -> bytes:
    """Build one searchable FDE for a VM blob that starts at function entry.

    The blob changes only ``rsp`` in its prologue, spills/restores registers, and
    returns to the native continuation. The FDE therefore describes the caller
    return address before the prologue and the VM frame after its seven-byte
    ``sub rsp, immediate`` instruction. ``call_ranges`` contains
    ``(start, end, cfa_offset)`` offsets for bridges whose hardware stack is
    temporarily relocated. When ``lsda_template`` is supplied, the FDE carries
    the original personality and a remapped call-site table.
    """
    if spec.blob_vaddr < 0 or spec.blob_size <= 0 or spec.blob_size > _MAX_U32:
        raise ValueError("VM unwind metadata requires a non-empty 32-bit blob range")
    if spec.frame_size <= 0 or spec.frame_size > _MAX_U32 - 8:
        raise ValueError("VM unwind metadata requires a positive 32-bit frame size")
    if spec.lsda_template is not None and spec.personality is None:
        raise ValueError("LSDA VM unwind metadata requires a personality routine")
    personality = spec.personality

    eh_frame_vaddr = spec.metadata_vaddr + _EH_FRAME_HEADER_SIZE
    if spec.lsda_template is None:
        cie = _cie()
    else:
        if personality is None:
            raise ValueError("LSDA VM unwind metadata requires a personality routine")
        cie = _cie_with_personality(eh_frame_vaddr, personality)
    lsda = b""
    lsda_vaddr: int | None = None
    if spec.lsda_template is not None:
        provisional = _fde(
            _FdeSpec(
                eh_frame_vaddr,
                spec.blob_vaddr,
                spec.blob_size,
                spec.frame_size,
                spec.call_ranges,
                cie,
                eh_frame_vaddr,
            )
        )
        lsda_vaddr = eh_frame_vaddr + len(provisional)
        lsda = _build_lsda(spec.blob_vaddr, spec.blob_size, spec.lsda_template, spec.lsda_call_sites, lsda_vaddr)
    eh_frame = _fde(
        _FdeSpec(
            eh_frame_vaddr,
            spec.blob_vaddr,
            spec.blob_size,
            spec.frame_size,
            spec.call_ranges,
            cie,
            lsda_vaddr,
        )
    )
    fde_vaddr = eh_frame_vaddr + len(cie)
    header = (
        bytes((1, _DW_EH_PE_PCREL_SDATA4, 0x03, _DW_EH_PE_DATAREL_SDATA4))
        + _sdata4(eh_frame_vaddr - (spec.metadata_vaddr + 4))
        + struct.pack("<I", 1)
        + _sdata4(spec.blob_vaddr - spec.metadata_vaddr)
        + _sdata4(fde_vaddr - spec.metadata_vaddr)
    )
    if len(header) != _EH_FRAME_HEADER_SIZE:
        raise ValueError("unexpected .eh_frame_hdr size")
    return header + eh_frame + lsda


def build_vm_eh_frame(
    blob_vaddr: int,
    blob_size: int,
    frame_size: int,
    metadata_vaddr: int,
    call_ranges: tuple[tuple[int, int, int], ...] = (),
) -> bytes:
    """Build ordinary unwind metadata for a VM blob."""
    return _build_vm_eh_frame(VmEhFrameSpec(blob_vaddr, blob_size, frame_size, metadata_vaddr, call_ranges))


def build_vm_eh_frame_with_lsda(spec: VmEhFrameSpec) -> bytes:
    """Build VM unwind metadata carrying a remapped LSDA call-site table."""
    if spec.lsda_template is None:
        raise ValueError("LSDA VM unwind metadata requires an LSDA template")
    return _build_vm_eh_frame(spec)


__all__ = ["_PT_GNU_EH_FRAME", "VmEhFrameSpec", "build_vm_eh_frame", "build_vm_eh_frame_with_lsda"]
