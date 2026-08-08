"""
Contract: the VM blob is injected in a brand-new load segment above the image.

The injector appends a page-aligned read/execute ``PT_LOAD`` mapped above every
pre-existing one, relocating the program-header table into that same segment so
it can grow by one entry (a typical image leaves no slack behind its table) and
so the kernel still derives ``AT_PHDR`` from a ``PT_LOAD`` containing
``e_phoff``. ET_EXEC and ET_DYN take the same path.

These tests drive the real injector against real ELF files and verify the
result by re-parsing the produced bytes with ``struct`` - an oracle independent
of the code that wrote them.
"""

from __future__ import annotations

import shutil
import struct
from dataclasses import dataclass
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization_inject import (
    _MAX_PHDR_ENTRIES,
    _PHDR_ENTRY_SIZE,
    _SEGMENT_ALIGN,
    _file_size,
    _read_physical,
    _write_physical,
    inject_blob,
    predict_blob_vaddr,
)

_DATASET = Path(__file__).resolve().parents[2] / "dataset"
# Non-PIE absolute image: p_vaddr values are the final runtime addresses.
_FIXTURE_EXEC = _DATASET / "elf_switch_abs_x86_64"
# Position-independent image: a RW/DYNAMIC load sits above the code, which the
# previous segment-extension scheme could never append past.
_FIXTURE_DYN = _DATASET / "elf_switch_pie_x86_64"
_FIXTURE_LARGE_WRITE = _DATASET / "elf_vm_arith_x86_64"

# ELF64 header field offsets used by the verification oracle.
_ELF64_HEADER_SIZE = 0x40
_E_PHOFF = 0x20
_E_PHNUM = 0x38
# p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align.
_PHDR_FORMAT = "<IIQQQQQQ"
_PT_NULL = 0
_PT_LOAD = 1
_PT_PHDR = 6
_PF_X = 0x1
_PF_R = 0x4
# Alignment a linker gives PT_PHDR: the table only needs natural 8-byte alignment.
_PHDR_TABLE_ALIGN = 8

_ET_EXEC = 2
_EM_X86_64 = 0x3E
_EV_CURRENT = 1
# Absolute base of the hand-built image; well clear of the fixtures' addresses.
_SYNTHETIC_IMAGE_BASE = 0x400000
_SYNTHETIC_PHNUM = 2
# xor edi, edi; mov eax, 60; syscall - never executed, it only gives the
# synthetic executable segment a plausible non-empty body.
_SYNTHETIC_CODE = b"\x31\xff\xb8\x3c\x00\x00\x00\x0f\x05"

_BLOB_SIZE = 256
_BLOB = bytes((index * 13 + 5) & 0xFF for index in range(_BLOB_SIZE))
# Comfortably past one r2 command buffer (~2 KiB of blob = ~4 KiB of hex).
_OVERSIZED_BLOB_SIZE = 8192


@dataclass(frozen=True)
class _Phdr:
    """One program-header entry, re-parsed from the produced file."""

    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _program_headers(path: Path) -> list[_Phdr]:
    """Re-parse a file's program-header table straight from its bytes."""
    raw = path.read_bytes()
    e_phoff = struct.unpack_from("<Q", raw, _E_PHOFF)[0]
    e_phnum = struct.unpack_from("<H", raw, _E_PHNUM)[0]
    return [_Phdr(*struct.unpack_from(_PHDR_FORMAT, raw, e_phoff + i * _PHDR_ENTRY_SIZE)) for i in range(e_phnum)]


def _copy_fixture(fixture: Path, tmp_path: Path) -> Path:
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    target = tmp_path / fixture.name
    shutil.copy(fixture, target)
    return target


def _inject_into(path: Path, blob: bytes) -> int | None:
    binary = Binary(str(path), writable=True)
    binary.open()
    try:
        return inject_blob(binary, blob)
    finally:
        binary.close()


def _predict_for(path: Path) -> int | None:
    binary = Binary(str(path), writable=True)
    binary.open()
    try:
        return predict_blob_vaddr(binary)
    finally:
        binary.close()


def _phdr_entry(p_type: int, p_flags: int, p_offset: int, p_vaddr: int, p_size: int, p_align: int) -> bytes:
    return struct.pack(_PHDR_FORMAT, p_type, p_flags, p_offset, p_vaddr, p_vaddr, p_size, p_size, p_align)


def _synthetic_phdr_table(e_phnum: int) -> bytes:
    """PT_PHDR plus one executable PT_LOAD, padded out with PT_NULL entries."""
    table_size = e_phnum * _PHDR_ENTRY_SIZE
    code_offset = _align_up(_ELF64_HEADER_SIZE + table_size, _SEGMENT_ALIGN)
    image_size = code_offset + len(_SYNTHETIC_CODE)
    table_vaddr = _SYNTHETIC_IMAGE_BASE + _ELF64_HEADER_SIZE
    entries = [
        _phdr_entry(_PT_PHDR, _PF_R, _ELF64_HEADER_SIZE, table_vaddr, table_size, _PHDR_TABLE_ALIGN),
        _phdr_entry(_PT_LOAD, _PF_R | _PF_X, 0, _SYNTHETIC_IMAGE_BASE, image_size, _SEGMENT_ALIGN),
    ]
    entries += [_phdr_entry(_PT_NULL, 0, 0, 0, 0, 0)] * (e_phnum - len(entries))
    return b"".join(entries)


def _elf64_header(entry: int, e_phnum: int, e_phentsize: int) -> bytes:
    header = bytearray(_ELF64_HEADER_SIZE)
    header[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 0x10, _ET_EXEC, _EM_X86_64, _EV_CURRENT)
    struct.pack_into("<QQQ", header, 0x18, entry, _ELF64_HEADER_SIZE, 0)
    struct.pack_into("<IHHHHHH", header, 0x30, 0, _ELF64_HEADER_SIZE, e_phentsize, e_phnum, 0, 0, 0)
    return bytes(header)


def _write_synthetic_elf(path: Path, e_phnum: int = _SYNTHETIC_PHNUM, e_phentsize: int = _PHDR_ENTRY_SIZE) -> Path:
    """Hand-build a minimal ELF64 carrying a PT_PHDR and an executable PT_LOAD."""
    table = _synthetic_phdr_table(e_phnum)
    code_offset = _align_up(_ELF64_HEADER_SIZE + len(table), _SEGMENT_ALIGN)
    image = bytearray(code_offset + len(_SYNTHETIC_CODE))
    image[0:_ELF64_HEADER_SIZE] = _elf64_header(_SYNTHETIC_IMAGE_BASE + code_offset, e_phnum, e_phentsize)
    image[_ELF64_HEADER_SIZE : _ELF64_HEADER_SIZE + len(table)] = table
    image[code_offset:] = _SYNTHETIC_CODE
    path.write_bytes(bytes(image))
    return path


def _blob_at(path: Path, vaddr: int, size: int) -> bytes:
    """Resolve ``vaddr`` to a file offset through the appended segment."""
    appended = _program_headers(path)[-1]
    offset = appended.p_offset + (vaddr - appended.p_vaddr)
    return path.read_bytes()[offset : offset + size]


def test_write_physical_round_trips_blob_larger_than_r2_command_buffer(tmp_path: Path) -> None:
    """A single ``wx`` is truncated past r2's ~4 KiB line buffer, so the writer chunks."""
    target = _copy_fixture(_FIXTURE_LARGE_WRITE, tmp_path)
    blob = bytes((index * 31 + 7) & 0xFF for index in range(_OVERSIZED_BLOB_SIZE))

    binary = Binary(str(target), writable=True)
    binary.open()
    try:
        offset = _file_size(binary)
        _write_physical(binary, offset, blob)
        readback = _read_physical(binary, offset, len(blob))
    finally:
        binary.close()

    assert readback == blob


def test_inject_blob_non_pie_binary_maps_blob_at_returned_vaddr(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_EXEC, tmp_path)

    injected = _inject_into(target, _BLOB)

    assert injected is not None and _blob_at(target, injected, _BLOB_SIZE) == _BLOB


def test_inject_blob_position_independent_binary_maps_blob_at_returned_vaddr(tmp_path: Path) -> None:
    """The ET_DYN case the previous segment-extension scheme always refused."""
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)

    injected = _inject_into(target, _BLOB)

    assert injected is not None and _blob_at(target, injected, _BLOB_SIZE) == _BLOB


def test_inject_blob_appended_segment_offset_is_congruent_with_its_vaddr(tmp_path: Path) -> None:
    """``p_offset == p_vaddr (mod p_align)``; a violating segment maps wrong."""
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)

    _inject_into(target, _BLOB)

    appended = _program_headers(target)[-1]
    assert appended.p_offset % _SEGMENT_ALIGN == appended.p_vaddr % _SEGMENT_ALIGN


def test_inject_blob_appended_segment_starts_above_every_existing_load(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    existing = [entry for entry in _program_headers(target) if entry.p_type == _PT_LOAD]

    _inject_into(target, _BLOB)

    appended = _program_headers(target)[-1]
    assert all(appended.p_vaddr >= entry.p_vaddr + entry.p_memsz for entry in existing)


def test_inject_blob_appends_a_read_execute_load_segment(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)

    _inject_into(target, _BLOB)

    appended = _program_headers(target)[-1]
    assert (appended.p_type, appended.p_flags) == (_PT_LOAD, _PF_R | _PF_X)


def test_predict_blob_vaddr_matches_the_vaddr_injection_returns(tmp_path: Path) -> None:
    """Callers hard-assert the two agree and roll the mutation back otherwise."""
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)

    predicted = _predict_for(target)

    assert predicted == _inject_into(target, _BLOB)


def test_inject_blob_increments_program_header_count_by_one(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    before = struct.unpack_from("<H", target.read_bytes(), _E_PHNUM)[0]

    _inject_into(target, _BLOB)

    assert struct.unpack_from("<H", target.read_bytes(), _E_PHNUM)[0] == before + 1


def test_inject_blob_relocates_phoff_inside_the_appended_segment(tmp_path: Path) -> None:
    """The kernel derives AT_PHDR from the PT_LOAD that contains e_phoff."""
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)

    _inject_into(target, _BLOB)

    e_phoff = struct.unpack_from("<Q", target.read_bytes(), _E_PHOFF)[0]
    appended = _program_headers(target)[-1]
    assert appended.p_offset <= e_phoff < appended.p_offset + appended.p_filesz


def test_inject_blob_retargets_pt_phdr_at_the_relocated_table(tmp_path: Path) -> None:
    """Without this a dynamic loader computes the wrong load bias for a PIE."""
    target = _write_synthetic_elf(tmp_path / "synthetic")

    _inject_into(target, _BLOB)

    headers = _program_headers(target)
    pt_phdr = next(entry for entry in headers if entry.p_type == _PT_PHDR)
    appended = headers[-1]
    expected = (appended.p_offset, appended.p_vaddr, len(headers) * _PHDR_ENTRY_SIZE)
    assert (pt_phdr.p_offset, pt_phdr.p_vaddr, pt_phdr.p_filesz) == expected


def test_inject_blob_refuses_unexpected_program_header_entry_size(tmp_path: Path) -> None:
    target = _write_synthetic_elf(tmp_path / "wide_entries", e_phentsize=_PHDR_ENTRY_SIZE + 8)

    assert _inject_into(target, _BLOB) is None


def test_inject_blob_refuses_program_header_count_at_the_growth_cap(tmp_path: Path) -> None:
    target = _write_synthetic_elf(tmp_path / "capped", e_phnum=_MAX_PHDR_ENTRIES)

    assert _inject_into(target, _BLOB) is None


def test_inject_blob_refusal_leaves_the_binary_untouched(tmp_path: Path) -> None:
    target = _write_synthetic_elf(tmp_path / "capped", e_phnum=_MAX_PHDR_ENTRIES)
    before = target.read_bytes()

    _inject_into(target, _BLOB)

    assert target.read_bytes() == before
