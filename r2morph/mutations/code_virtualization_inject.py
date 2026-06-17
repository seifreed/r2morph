"""
radare2-native executable-region injection for code virtualization.

Places a generated VM interpreter blob into an ELF64 binary by extending
its executable ``PT_LOAD`` segment: the blob is appended past end-of-file
and the segment's ``p_filesz``/``p_memsz`` are grown to map it executable.
All reads and writes go through the binary's radare2 session - r2 owns the
file layout, so the trampoline (a normal virtual-address write) and the
appended blob stay consistent and survive ``save``.

The injector refuses (returns ``None``) whenever the extension cannot be
proven safe: non-ELF64, no executable ``PT_LOAD``, or a grown segment that
would overlap another loadable segment's virtual-address range. A refused
injection leaves the binary untouched.
"""

from __future__ import annotations

import logging
import struct
from typing import Any

logger = logging.getLogger(__name__)

_ELF64_MAGIC = b"\x7fELF"
_ELFCLASS64 = 2
_PT_LOAD = 1
_PF_X = 0x1
# ELF64 program-header field offsets relative to the entry start.
_P_FLAGS = 0x04
_P_OFFSET = 0x08
_P_VADDR = 0x10
_P_FILESZ = 0x20
_P_MEMSZ = 0x28


class ExecSegment:
    """Located executable PT_LOAD plus the other loadable vaddr ranges."""

    __slots__ = ("phdr_offset", "file_offset", "vaddr", "filesz", "memsz", "other_ranges")

    def __init__(
        self,
        phdr_offset: int,
        file_offset: int,
        vaddr: int,
        filesz: int,
        memsz: int,
        other_ranges: list[tuple[int, int]],
    ) -> None:
        self.phdr_offset = phdr_offset
        self.file_offset = file_offset
        self.vaddr = vaddr
        self.filesz = filesz
        self.memsz = memsz
        self.other_ranges = other_ranges


# r2 truncates a single command past its line buffer (~4 KiB), so each `wx`/`p8`
# carries at most this many bytes (2x hex chars); larger blobs are chunked. A VM
# blob with nesting easily exceeds one buffer, so an unchunked write silently
# corrupted the tail and the injection's read-back rejected it.
_IO_CHUNK = 1024


def _read_physical(binary: Any, offset: int, size: int) -> bytes:
    """Read raw file bytes through r2 (physical addressing)."""
    binary.r2.cmd("e io.va=0")
    try:
        out = bytearray()
        for pos in range(0, size, _IO_CHUNK):
            hexout = binary.r2.cmd(f"p8 {min(_IO_CHUNK, size - pos)} @ {offset + pos}").strip()
            if hexout:
                out += bytes.fromhex(hexout)
    finally:
        binary.r2.cmd("e io.va=1")
    return bytes(out)


def _write_physical(binary: Any, offset: int, data: bytes) -> None:
    """Write raw file bytes through r2 (physical addressing, grows file)."""
    binary.r2.cmd("e io.va=0")
    try:
        for pos in range(0, len(data), _IO_CHUNK):
            chunk = data[pos : pos + _IO_CHUNK]
            binary.r2.cmd(f"wx {chunk.hex()} @ {offset + pos}")
    finally:
        binary.r2.cmd("e io.va=1")


def _file_size(binary: Any) -> int:
    info = binary.r2.cmdj("ij") or {}
    size = info.get("core", {}).get("size")
    return int(size) if size else 0


def _r2_segment_vaddr(binary: Any, paddr: int) -> int | None:
    """Map a file offset to r2's load address for that segment.

    r2 may rebase a binary (it reports the entrypoint and instruction
    addresses in this space), so blob/trampoline math must use r2's vaddr,
    not the on-disk ``p_vaddr``. rel32 offsets are base-independent, so the
    produced jumps remain correct at the real runtime load address.
    """
    segments = binary.r2.cmdj("iSSj") or []
    for segment in segments:
        if segment.get("paddr") == paddr and "x" in segment.get("perm", ""):
            vaddr = segment.get("vaddr")
            return int(vaddr) if vaddr is not None else None
    return None


def locate_exec_segment(binary: Any) -> ExecSegment | None:
    """Locate the executable PT_LOAD of an ELF64 binary, or ``None``."""
    header = _read_physical(binary, 0, 64)
    if len(header) < 64 or header[:4] != _ELF64_MAGIC or header[4] != _ELFCLASS64:
        return None

    e_phoff = struct.unpack_from("<Q", header, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", header, 0x36)[0]
    e_phnum = struct.unpack_from("<H", header, 0x38)[0]
    if e_phoff == 0 or e_phentsize < 0x38 or e_phnum == 0:
        return None

    table = _read_physical(binary, e_phoff, e_phentsize * e_phnum)
    if len(table) < e_phentsize * e_phnum:
        return None

    exec_seg: ExecSegment | None = None
    load_offsets: list[tuple[int, int]] = []
    for index in range(e_phnum):
        base = index * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", table, base)
        if p_type != _PT_LOAD:
            continue
        p_offset = struct.unpack_from("<Q", table, base + _P_OFFSET)[0]
        p_filesz = struct.unpack_from("<Q", table, base + _P_FILESZ)[0]
        p_memsz = struct.unpack_from("<Q", table, base + _P_MEMSZ)[0]
        load_offsets.append((p_offset, p_memsz))
        if p_flags & _PF_X and exec_seg is None:
            r2_vaddr = _r2_segment_vaddr(binary, p_offset)
            if r2_vaddr is None:
                return None
            exec_seg = ExecSegment(e_phoff + base, p_offset, r2_vaddr, p_filesz, p_memsz, [])

    if exec_seg is None:
        return None

    # Map other loadable segments into r2's address space for the overlap gate.
    other: list[tuple[int, int]] = []
    for p_offset, p_memsz in load_offsets:
        if p_offset == exec_seg.file_offset:
            continue
        vaddr = _r2_segment_vaddr_any(binary, p_offset)
        if vaddr is not None:
            other.append((vaddr, vaddr + p_memsz))
    exec_seg.other_ranges = other
    return exec_seg


def _r2_segment_vaddr_any(binary: Any, paddr: int) -> int | None:
    """Map a file offset to r2's load address for any loadable segment."""
    segments = binary.r2.cmdj("iSSj") or []
    for segment in segments:
        if segment.get("paddr") == paddr and segment.get("name", "").startswith("LOAD"):
            vaddr = segment.get("vaddr")
            return int(vaddr) if vaddr is not None else None
    return None


def predict_blob_vaddr(binary: Any) -> int | None:
    """
    Predict the vaddr the next appended blob will map at, without writing.

    The interpreter encodes an absolute ``jmp continuation`` whose rel32 we
    must resolve before assembly, so callers need the destination vaddr up
    front. Returns ``None`` when injection would be unsafe for the same
    reasons as :func:`inject_blob`.
    """
    segment = locate_exec_segment(binary)
    if segment is None:
        return None
    file_size = _file_size(binary)
    if file_size <= segment.file_offset:
        return None
    return segment.vaddr + (file_size - segment.file_offset)


def inject_blob(binary: Any, blob: bytes) -> int | None:
    """
    Append ``blob`` and extend the executable segment to map it.

    Returns the virtual address the blob is mapped at, or ``None`` when the
    extension cannot be proven safe (binary left untouched).
    """
    segment = locate_exec_segment(binary)
    if segment is None:
        logger.debug("No ELF64 executable segment to extend; skipping virtualization")
        return None

    file_size = _file_size(binary)
    if file_size <= segment.file_offset:
        return None

    blob_offset = file_size
    blob_vaddr = segment.vaddr + (blob_offset - segment.file_offset)
    new_segment_size = blob_offset + len(blob) - segment.file_offset
    new_segment_end = segment.vaddr + new_segment_size

    for other_start, other_end in segment.other_ranges:
        if blob_vaddr < other_end and other_start < new_segment_end:
            logger.debug(
                "Extended exec segment [0x%x,0x%x) would overlap load range [0x%x,0x%x); skipping",
                segment.vaddr,
                new_segment_end,
                other_start,
                other_end,
            )
            return None

    _write_physical(binary, blob_offset, blob)
    size_bytes = struct.pack("<Q", new_segment_size)
    _write_physical(binary, segment.phdr_offset + _P_FILESZ, size_bytes)
    _write_physical(binary, segment.phdr_offset + _P_MEMSZ, size_bytes)

    written = _read_physical(binary, blob_offset, len(blob))
    if written != blob:
        logger.warning("VM blob read-back mismatch at file offset 0x%x; injection failed", blob_offset)
        return None

    logger.debug("Injected %d-byte VM blob at vaddr 0x%x (file 0x%x)", len(blob), blob_vaddr, blob_offset)
    return blob_vaddr
