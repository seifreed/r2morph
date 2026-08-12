"""
radare2-native executable-region injection for code virtualization.

Places a generated VM interpreter blob into an ELF64 binary by appending a
read/execute ``PT_LOAD`` segment above every existing one. Later blobs extend
that terminal segment when its geometry proves it owns the end of the file,
instead of exposing one extra load segment per virtualized function. ET_EXEC
and ET_DYN images take the identical path.

A typical image leaves no slack after its program-header table (``.gnu.hash``
starts immediately behind it), so the table cannot simply grow in place: the
whole table is copied into the appended region and grown by one entry there.
Keeping the relocated table *inside* the new segment is what preserves
``AT_PHDR`` - the kernel derives it from whichever ``PT_LOAD`` contains
``e_phoff`` - which static-PIE startup depends on. A ``PT_PHDR`` entry, when
present, is retargeted at the relocated table so a dynamic loader still
computes the right load bias.

All reads and writes go through the binary's radare2 session - r2 owns the
file layout, so the trampoline (a normal virtual-address write) and the
appended segment stay consistent and survive ``save``.

The injector refuses (returns ``None``) for a binary whose geometry it cannot
describe: non-ELF64, an unexpected program-header entry size, a missing
program-header table, no executable ``PT_LOAD`` to anchor r2's address space
against, or a program-header count already at the growth cap. A refused
injection leaves the binary untouched.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

_ELF64_MAGIC = b"\x7fELF"
_ELFCLASS64 = 2
_ELF64_HEADER_SIZE = 0x40
# ELF64 header field offsets.
_E_PHOFF = 0x20
_E_PHENTSIZE = 0x36
_E_PHNUM = 0x38
# ELF64 program-header entry size and field offsets relative to the entry start.
_PHDR_ENTRY_SIZE = 0x38
_P_TYPE = 0x00
_P_FLAGS = 0x04
_P_OFFSET = 0x08
_P_VADDR = 0x10
_P_PADDR = 0x18
_P_FILESZ = 0x20
_P_MEMSZ = 0x28
_P_ALIGN = 0x30
_PT_LOAD = 1
_PT_PHDR = 6
_PF_X = 0x1
_PF_R = 0x4
# Segment alignment. Both the appended file offset and the new virtual address
# are rounded to it, which satisfies the loader's `p_offset == p_vaddr (mod
# p_align)` congruence requirement trivially; a violating segment would be
# mapped from the wrong file offset.
_SEGMENT_ALIGN = 0x1000
# Each injection adds one program header, so the table would grow without bound
# over a long mutation run. Refuse past this many entries.
_MAX_PHDR_ENTRIES = 128

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
    """Map a file offset to r2's load address for that executable segment.

    r2 may rebase a binary (it reports the entrypoint and instruction
    addresses in this space), so blob/trampoline math must be expressed in
    r2's vaddr space, not in the on-disk ``p_vaddr`` space.
    """
    segments = binary.r2.cmdj("iSSj") or []
    for segment in segments:
        if segment.get("paddr") == paddr and "x" in segment.get("perm", ""):
            vaddr = segment.get("vaddr")
            return int(vaddr) if vaddr is not None else None
    return None


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass(frozen=True)
class _Load:
    """One ``PT_LOAD`` entry of the on-disk program-header table."""

    offset: int
    vaddr: int
    memsz: int
    flags: int


@dataclass(frozen=True)
class _Placement:
    """Where the next appended segment lands.

    Every field is derived from file size and header geometry alone - never
    from the blob - so :func:`predict_blob_vaddr` and :func:`inject_blob`
    compute an identical placement for the same binary.
    """

    file_size: int
    append_offset: int
    segment_vaddr: int
    phdr_table_size: int
    blob_vaddr: int
    e_phoff: int
    e_phnum: int
    table: bytes


@dataclass(frozen=True)
class _Reuse:
    """A terminal executable segment that can safely absorb another blob."""

    blob_offset: int
    blob_vaddr: int
    entry_offset: int
    segment_size: int


def _phdr_table_geometry(header: bytes) -> tuple[int, int] | None:
    """``(e_phoff, e_phnum)`` of a growable ELF64 program-header table."""
    if len(header) < _ELF64_HEADER_SIZE or header[:4] != _ELF64_MAGIC or header[4] != _ELFCLASS64:
        return None
    e_phoff = struct.unpack_from("<Q", header, _E_PHOFF)[0]
    e_phentsize = struct.unpack_from("<H", header, _E_PHENTSIZE)[0]
    e_phnum = struct.unpack_from("<H", header, _E_PHNUM)[0]
    if e_phoff == 0 or e_phnum == 0 or e_phentsize != _PHDR_ENTRY_SIZE:
        return None
    if e_phnum >= _MAX_PHDR_ENTRIES:
        logger.debug("Program-header table already holds %d entries (cap %d); skipping", e_phnum, _MAX_PHDR_ENTRIES)
        return None
    return e_phoff, e_phnum


def _parse_loads(table: bytes, e_phnum: int) -> list[_Load]:
    """Every ``PT_LOAD`` entry of a program-header table, in table order."""
    loads: list[_Load] = []
    for index in range(e_phnum):
        base = index * _PHDR_ENTRY_SIZE
        p_type, p_flags = struct.unpack_from("<II", table, base + _P_TYPE)
        if p_type != _PT_LOAD:
            continue
        loads.append(
            _Load(
                offset=struct.unpack_from("<Q", table, base + _P_OFFSET)[0],
                vaddr=struct.unpack_from("<Q", table, base + _P_VADDR)[0],
                memsz=struct.unpack_from("<Q", table, base + _P_MEMSZ)[0],
                flags=p_flags,
            )
        )
    return loads


def _exec_anchor(binary: Any, loads: list[_Load]) -> tuple[int, int] | None:
    """``(on-disk p_vaddr, r2 vaddr)`` of the first executable ``PT_LOAD``.

    The pair is the rebase anchor: the delta between an on-disk virtual
    address and r2's view of it is constant across the whole image, so a
    fabricated on-disk address can be translated into r2 space through it.
    """
    for load in loads:
        if not load.flags & _PF_X:
            continue
        r2_vaddr = _r2_segment_vaddr(binary, load.offset)
        return None if r2_vaddr is None else (load.vaddr, r2_vaddr)
    return None


def _plan_placement(binary: Any) -> _Placement | None:
    """Compute where a new segment would be appended, without writing."""
    header = _read_physical(binary, 0, _ELF64_HEADER_SIZE)
    geometry = _phdr_table_geometry(header)
    if geometry is None:
        return None
    e_phoff, e_phnum = geometry

    table_size = e_phnum * _PHDR_ENTRY_SIZE
    table = _read_physical(binary, e_phoff, table_size)
    if len(table) < table_size:
        return None

    loads = _parse_loads(table, e_phnum)
    anchor = _exec_anchor(binary, loads)
    file_size = _file_size(binary)
    if anchor is None or file_size <= 0:
        return None

    exec_vaddr, exec_r2_vaddr = anchor
    segment_vaddr = _align_up(max(load.vaddr + load.memsz for load in loads), _SEGMENT_ALIGN)
    phdr_table_size = (e_phnum + 1) * _PHDR_ENTRY_SIZE
    return _Placement(
        file_size=file_size,
        append_offset=_align_up(file_size, _SEGMENT_ALIGN),
        segment_vaddr=segment_vaddr,
        phdr_table_size=phdr_table_size,
        blob_vaddr=exec_r2_vaddr + (segment_vaddr + phdr_table_size - exec_vaddr),
        e_phoff=e_phoff,
        e_phnum=e_phnum,
        table=table,
    )


def _plan_reuse(placement: _Placement) -> _Reuse | None:
    """Reuse the relocated-table segment when it exclusively owns EOF."""
    base = (placement.e_phnum - 1) * _PHDR_ENTRY_SIZE
    p_type, p_flags = struct.unpack_from("<II", placement.table, base + _P_TYPE)
    offset = struct.unpack_from("<Q", placement.table, base + _P_OFFSET)[0]
    vaddr = struct.unpack_from("<Q", placement.table, base + _P_VADDR)[0]
    filesz = struct.unpack_from("<Q", placement.table, base + _P_FILESZ)[0]
    memsz = struct.unpack_from("<Q", placement.table, base + _P_MEMSZ)[0]
    loads = _parse_loads(placement.table, placement.e_phnum)
    if (
        p_type != _PT_LOAD
        or p_flags != _PF_R | _PF_X
        or offset != placement.e_phoff
        or offset + filesz != placement.file_size
        or filesz != memsz
        or vaddr + memsz != max(load.vaddr + load.memsz for load in loads)
    ):
        return None

    rebase_delta = placement.blob_vaddr - placement.segment_vaddr - placement.phdr_table_size
    return _Reuse(
        blob_offset=placement.file_size,
        blob_vaddr=vaddr + filesz + rebase_delta,
        entry_offset=placement.e_phoff + base,
        segment_size=filesz,
    )


def _retarget_phdr_entry(table: bytearray, base: int, placement: _Placement) -> None:
    """Point a ``PT_PHDR`` entry at the relocated program-header table."""
    struct.pack_into("<Q", table, base + _P_OFFSET, placement.append_offset)
    struct.pack_into("<Q", table, base + _P_VADDR, placement.segment_vaddr)
    struct.pack_into("<Q", table, base + _P_PADDR, placement.segment_vaddr)
    struct.pack_into("<Q", table, base + _P_FILESZ, placement.phdr_table_size)
    struct.pack_into("<Q", table, base + _P_MEMSZ, placement.phdr_table_size)


def _new_load_entry(placement: _Placement, blob_size: int) -> bytes:
    """The appended read/execute ``PT_LOAD`` covering table plus blob."""
    segment_size = placement.phdr_table_size + blob_size
    entry = bytearray(_PHDR_ENTRY_SIZE)
    struct.pack_into("<II", entry, _P_TYPE, _PT_LOAD, _PF_R | _PF_X)
    struct.pack_into("<Q", entry, _P_OFFSET, placement.append_offset)
    struct.pack_into("<Q", entry, _P_VADDR, placement.segment_vaddr)
    struct.pack_into("<Q", entry, _P_PADDR, placement.segment_vaddr)
    struct.pack_into("<Q", entry, _P_FILESZ, segment_size)
    struct.pack_into("<Q", entry, _P_MEMSZ, segment_size)
    struct.pack_into("<Q", entry, _P_ALIGN, _SEGMENT_ALIGN)
    return bytes(entry)


def _header_load_index(table: bytes, e_phnum: int) -> int | None:
    """Index of the ``PT_LOAD`` that maps the ELF header, if any."""
    for index in range(e_phnum):
        base = index * _PHDR_ENTRY_SIZE
        if struct.unpack_from("<I", table, base + _P_TYPE)[0] != _PT_LOAD:
            continue
        if struct.unpack_from("<Q", table, base + _P_OFFSET)[0] == 0:
            return index
    return None


def _grow_header_segment(table: bytearray, placement: _Placement) -> None:
    """Keep the ELF header's segment spanning the grown program-header table.

    Adding an entry lengthens the header-plus-table prefix, and a loader that
    locates the table from the image base rather than from ``AT_PHDR`` rejects
    an image whose first loadable segment is shorter than that prefix. The
    Linux kernel does not check it, so failing to grow is not fatal - but the
    grown segment costs nothing and keeps the output acceptable to both. The
    segment is only stretched into space the next one does not already claim.
    """
    index = _header_load_index(bytes(table), placement.e_phnum)
    if index is None:
        return
    required = _ELF64_HEADER_SIZE + (placement.e_phnum + 1) * _PHDR_ENTRY_SIZE
    base = index * _PHDR_ENTRY_SIZE
    vaddr = struct.unpack_from("<Q", table, base + _P_VADDR)[0]
    if struct.unpack_from("<Q", table, base + _P_FILESZ)[0] >= required or required > placement.file_size:
        return

    loads = _parse_loads(bytes(table), placement.e_phnum)
    ceiling = min((load.vaddr for load in loads if load.vaddr > vaddr), default=None)
    if ceiling is not None and vaddr + required > ceiling:
        logger.debug("No room to span the program-header table in the header segment at 0x%x; leaving it", vaddr)
        return

    memsz = struct.unpack_from("<Q", table, base + _P_MEMSZ)[0]
    struct.pack_into("<Q", table, base + _P_FILESZ, required)
    struct.pack_into("<Q", table, base + _P_MEMSZ, max(memsz, required))


def _relocated_phdr_table(placement: _Placement, blob_size: int) -> bytes:
    """The original entries, ``PT_PHDR`` retargeted, plus the new ``PT_LOAD``.

    The new entry goes last and has the highest virtual address: the kernel
    sizes an ET_DYN total mapping from the last ``PT_LOAD`` in table order.
    """
    table = bytearray(placement.table)
    for index in range(placement.e_phnum):
        base = index * _PHDR_ENTRY_SIZE
        if struct.unpack_from("<I", table, base + _P_TYPE)[0] == _PT_PHDR:
            _retarget_phdr_entry(table, base, placement)
    _grow_header_segment(table, placement)
    return bytes(table) + _new_load_entry(placement, blob_size)


def predict_blob_vaddr(binary: Any) -> int | None:
    """
    Predict the vaddr the next appended blob will map at, without writing.

    The interpreter encodes an absolute ``jmp continuation`` whose rel32 we
    must resolve before assembly, so callers need the destination vaddr up
    front. The placement never depends on the blob, so this is exactly the
    address :func:`inject_blob` returns. Returns ``None`` whenever injection
    would be refused, for the same reasons.
    """
    placement = _plan_placement(binary)
    if placement is None:
        return None
    reuse = _plan_reuse(placement)
    return reuse.blob_vaddr if reuse is not None else placement.blob_vaddr


def _extend_segment(binary: Any, reuse: _Reuse, blob: bytes) -> int | None:
    """Append ``blob`` and grow the owning terminal load entry in place."""
    segment_size = reuse.segment_size + len(blob)
    _write_physical(binary, reuse.blob_offset, blob)
    _write_physical(binary, reuse.entry_offset + _P_FILESZ, struct.pack("<Q", segment_size))
    _write_physical(binary, reuse.entry_offset + _P_MEMSZ, struct.pack("<Q", segment_size))
    if _read_physical(binary, reuse.blob_offset, len(blob)) != blob:
        logger.warning("VM blob read-back mismatch at file offset 0x%x; injection failed", reuse.blob_offset)
        return None
    logger.debug(
        "Injected %d-byte VM blob at vaddr 0x%x by extending the terminal load segment",
        len(blob),
        reuse.blob_vaddr,
    )
    return reuse.blob_vaddr


def inject_blob(binary: Any, blob: bytes) -> int | None:
    """
    Append ``blob`` in a new executable segment mapped above the whole image.

    Returns the virtual address (in r2's address space) the blob is mapped
    at, or ``None`` when the binary's geometry does not admit a new segment
    (the binary is left untouched).
    """
    placement = _plan_placement(binary)
    if placement is None:
        logger.debug("ELF64 geometry admits no appended load segment; skipping virtualization")
        return None
    reuse = _plan_reuse(placement)
    if reuse is not None:
        return _extend_segment(binary, reuse, blob)

    padding = bytes(placement.append_offset - placement.file_size)
    _write_physical(binary, placement.file_size, padding + _relocated_phdr_table(placement, len(blob)) + blob)
    _write_physical(binary, _E_PHOFF, struct.pack("<Q", placement.append_offset))
    _write_physical(binary, _E_PHNUM, struct.pack("<H", placement.e_phnum + 1))

    blob_offset = placement.append_offset + placement.phdr_table_size
    if _read_physical(binary, blob_offset, len(blob)) != blob:
        logger.warning("VM blob read-back mismatch at file offset 0x%x; injection failed", blob_offset)
        return None

    logger.debug(
        "Injected %d-byte VM blob at vaddr 0x%x (file 0x%x) in a new load segment",
        len(blob),
        placement.blob_vaddr,
        blob_offset,
    )
    return placement.blob_vaddr
