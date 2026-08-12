"""
Contract: VM blobs occupy adjacent fragmented loads above the image.

The injector relocates the program-header table into a page-aligned read-only
``PT_LOAD`` and maps each VM blob through adjacent read/execute fragments. This
keeps the VM's address range contiguous while denying static tools one large RX
container. ET_EXEC and ET_DYN take the same path.

These tests drive the real injector against real ELF files and verify the
result by re-parsing the produced bytes with ``struct`` - an oracle independent
of the code that wrote them. Beyond the individual field assertions, every
produced image is held up against the full set of loader invariants in
``tests.utils.elf_load_invariants``, because an emulator will run a
structurally invalid image without complaint and only a strict loader would
otherwise notice.
"""

from __future__ import annotations

import itertools
import shutil
import struct
from dataclasses import astuple, replace
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization_inject import (
    _MAX_PHDR_ENTRIES,
    _PHDR_ENTRY_SIZE,
    _SEGMENT_ALIGN,
    _file_size,
    _fragment_sizes,
    _read_physical,
    _write_physical,
    inject_blob,
    predict_blob_vaddr,
)
from tests.utils.elf_load_invariants import (
    ELF64_HEADER_SIZE,
    HEADER_SEGMENT_SPAN,
    LOAD_VADDR_OVERLAP,
    PHDR_FORMAT,
    PT_LOAD,
    PT_PHDR,
    ProgramHeader,
    assert_loadable,
    load_invariant_violations,
    program_headers,
)

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
# Non-PIE absolute image: p_vaddr values are the final runtime addresses.
_FIXTURE_EXEC = _DATASET / "elf_switch_abs_x86_64"
# Position-independent image: a RW/DYNAMIC load sits above the code, which the
# previous segment-extension scheme could never append past.
_FIXTURE_DYN = _DATASET / "elf_switch_pie_x86_64"
_FIXTURE_LARGE_WRITE = _DATASET / "elf_vm_arith_x86_64"

# ELF64 header field offsets used by the verification oracle.
_E_PHOFF = 0x20
_E_PHNUM = 0x38
_PT_NULL = 0
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
_FRAGMENTED_BLOB_SIZE = 0x9000


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _overwrite_program_header(path: Path, index: int, header: ProgramHeader) -> None:
    """Put ``header`` back at entry ``index``, to hand the oracle a broken image."""
    raw = bytearray(path.read_bytes())
    e_phoff = struct.unpack_from("<Q", raw, _E_PHOFF)[0]
    struct.pack_into(PHDR_FORMAT, raw, e_phoff + index * _PHDR_ENTRY_SIZE, *astuple(header))
    path.write_bytes(bytes(raw))


def _header_segment_index(path: Path) -> int:
    """Index of the PT_LOAD that maps the ELF header itself."""
    headers = program_headers(path)
    return next(i for i, entry in enumerate(headers) if entry.p_type == PT_LOAD and entry.p_offset == 0)


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
    return struct.pack(PHDR_FORMAT, p_type, p_flags, p_offset, p_vaddr, p_vaddr, p_size, p_size, p_align)


def _synthetic_phdr_table(e_phnum: int) -> bytes:
    """PT_PHDR plus one executable PT_LOAD, padded out with PT_NULL entries."""
    table_size = e_phnum * _PHDR_ENTRY_SIZE
    code_offset = _align_up(ELF64_HEADER_SIZE + table_size, _SEGMENT_ALIGN)
    image_size = code_offset + len(_SYNTHETIC_CODE)
    table_vaddr = _SYNTHETIC_IMAGE_BASE + ELF64_HEADER_SIZE
    entries = [
        _phdr_entry(PT_PHDR, _PF_R, ELF64_HEADER_SIZE, table_vaddr, table_size, _PHDR_TABLE_ALIGN),
        _phdr_entry(PT_LOAD, _PF_R | _PF_X, 0, _SYNTHETIC_IMAGE_BASE, image_size, _SEGMENT_ALIGN),
    ]
    entries += [_phdr_entry(_PT_NULL, 0, 0, 0, 0, 0)] * (e_phnum - len(entries))
    return b"".join(entries)


def _elf64_header(entry: int, e_phnum: int, e_phentsize: int) -> bytes:
    header = bytearray(ELF64_HEADER_SIZE)
    header[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 0x10, _ET_EXEC, _EM_X86_64, _EV_CURRENT)
    struct.pack_into("<QQQ", header, 0x18, entry, ELF64_HEADER_SIZE, 0)
    struct.pack_into("<IHHHHHH", header, 0x30, 0, ELF64_HEADER_SIZE, e_phentsize, e_phnum, 0, 0, 0)
    return bytes(header)


def _write_synthetic_elf(path: Path, e_phnum: int = _SYNTHETIC_PHNUM, e_phentsize: int = _PHDR_ENTRY_SIZE) -> Path:
    """Hand-build a minimal ELF64 carrying a PT_PHDR and an executable PT_LOAD."""
    table = _synthetic_phdr_table(e_phnum)
    code_offset = _align_up(ELF64_HEADER_SIZE + len(table), _SEGMENT_ALIGN)
    image = bytearray(code_offset + len(_SYNTHETIC_CODE))
    image[0:ELF64_HEADER_SIZE] = _elf64_header(_SYNTHETIC_IMAGE_BASE + code_offset, e_phnum, e_phentsize)
    image[ELF64_HEADER_SIZE : ELF64_HEADER_SIZE + len(table)] = table
    image[code_offset:] = _SYNTHETIC_CODE
    path.write_bytes(bytes(image))
    return path


def _blob_at(path: Path, vaddr: int, size: int) -> bytes:
    """Resolve ``vaddr`` to the contiguous file bytes behind RX fragments."""
    owner = next(
        entry
        for entry in program_headers(path)
        if entry.p_type == PT_LOAD and entry.p_vaddr <= vaddr < entry.p_vaddr + entry.p_memsz
    )
    offset = owner.p_offset + (vaddr - owner.p_vaddr)
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

    appended = program_headers(target)[-1]
    assert appended.p_offset % _SEGMENT_ALIGN == appended.p_vaddr % _SEGMENT_ALIGN


def test_inject_blob_appended_segment_starts_above_every_existing_load(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    existing = [entry for entry in program_headers(target) if entry.p_type == PT_LOAD]

    _inject_into(target, _BLOB)

    appended = program_headers(target)[-1]
    assert all(appended.p_vaddr >= entry.p_vaddr + entry.p_memsz for entry in existing)


def test_inject_blob_appends_a_read_execute_load_segment(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)

    _inject_into(target, _BLOB)

    appended = program_headers(target)[-1]
    assert (appended.p_type, appended.p_flags) == (PT_LOAD, _PF_R | _PF_X)


def test_predict_blob_vaddr_matches_the_vaddr_injection_returns(tmp_path: Path) -> None:
    """Callers hard-assert the two agree and roll the mutation back otherwise."""
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)

    predicted = _predict_for(target)

    assert predicted == _inject_into(target, _BLOB)


def test_inject_blob_adds_table_load_and_rx_fragments(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    before = struct.unpack_from("<H", target.read_bytes(), _E_PHNUM)[0]

    _inject_into(target, _BLOB)

    assert struct.unpack_from("<H", target.read_bytes(), _E_PHNUM)[0] == before + 1 + len(_fragment_sizes(_BLOB))


def test_second_blob_adds_its_own_table_and_fragment_headers(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    _inject_into(target, _BLOB)
    after_first = struct.unpack_from("<H", target.read_bytes(), _E_PHNUM)[0]

    _inject_into(target, _BLOB[::-1])

    assert struct.unpack_from("<H", target.read_bytes(), _E_PHNUM)[0] == after_first + 1 + len(
        _fragment_sizes(_BLOB[::-1])
    )


def test_second_fragmented_blob_maps_each_blob_at_its_returned_address(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)

    first = _inject_into(target, _BLOB)
    second = _inject_into(target, _BLOB[::-1])

    assert (
        first is not None
        and second is not None
        and (
            _blob_at(target, first, _BLOB_SIZE),
            _blob_at(target, second, _BLOB_SIZE),
        )
        == (_BLOB, _BLOB[::-1])
    )


def test_predict_second_blob_address_matches_fragmented_injection(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    _inject_into(target, _BLOB)

    predicted = _predict_for(target)

    assert predicted == _inject_into(target, _BLOB[::-1])


def test_second_fragmented_blob_preserves_strict_loader_invariants(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    _inject_into(target, _BLOB)

    _inject_into(target, _BLOB[::-1])

    assert_loadable(target)


def test_inject_blob_relocates_phoff_inside_a_read_only_load(tmp_path: Path) -> None:
    """The kernel derives AT_PHDR from the PT_LOAD that contains e_phoff."""
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)

    _inject_into(target, _BLOB)

    e_phoff = struct.unpack_from("<Q", target.read_bytes(), _E_PHOFF)[0]
    owner = next(
        entry
        for entry in program_headers(target)
        if entry.p_type == PT_LOAD and entry.p_offset <= e_phoff < entry.p_offset + entry.p_filesz
    )
    assert owner.p_flags == _PF_R


def test_inject_blob_retargets_pt_phdr_at_the_relocated_table(tmp_path: Path) -> None:
    """Without this a dynamic loader computes the wrong load bias for a PIE."""
    target = _write_synthetic_elf(tmp_path / "synthetic")

    _inject_into(target, _BLOB)

    headers = program_headers(target)
    pt_phdr = next(entry for entry in headers if entry.p_type == PT_PHDR)
    e_phoff = struct.unpack_from("<Q", target.read_bytes(), _E_PHOFF)[0]
    table_load = next(entry for entry in headers if entry.p_type == PT_LOAD and entry.p_offset == e_phoff)
    expected = (table_load.p_offset, table_load.p_vaddr, len(headers) * _PHDR_ENTRY_SIZE)
    assert (pt_phdr.p_offset, pt_phdr.p_vaddr, pt_phdr.p_filesz) == expected


def test_large_blob_is_split_into_adjacent_rx_fragments(tmp_path: Path) -> None:
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    blob = bytes((index * 17 + 3) & 0xFF for index in range(_FRAGMENTED_BLOB_SIZE))
    before = len(program_headers(target))

    injected = _inject_into(target, blob)

    fragments = program_headers(target)[before + 1 :]
    assert (
        injected is not None
        and len(fragments) > 1
        and all((entry.p_type, entry.p_flags) == (PT_LOAD, _PF_R | _PF_X) for entry in fragments)
        and all(
            left.p_vaddr + left.p_memsz == right.p_vaddr and left.p_offset + left.p_filesz == right.p_offset
            for left, right in itertools.pairwise(fragments)
        )
        and _blob_at(target, injected, len(blob)) == blob
    )


@pytest.mark.parametrize("fixture", [_FIXTURE_EXEC, _FIXTURE_DYN])
def test_inject_blob_keeps_the_header_segment_spanning_the_program_header_table(fixture: Path, tmp_path: Path) -> None:
    # Appending an entry lengthens the ELF-header-plus-table prefix. A loader that
    # locates the table from the image base instead of AT_PHDR refuses an image whose
    # first loadable segment is shorter than that prefix - observed as a hard refusal
    # ("first load segment does not span the elf header size") on an image whose
    # header segment covered 457 of the 512 bytes the grown table needed.
    target = _copy_fixture(fixture, tmp_path)

    _inject_into(target, _BLOB)

    headers = program_headers(target)
    header_segment = next(e for e in headers if e.p_type == PT_LOAD and e.p_offset == 0)
    assert header_segment.p_filesz >= ELF64_HEADER_SIZE + len(headers) * _PHDR_ENTRY_SIZE


@pytest.mark.parametrize("fixture", [_FIXTURE_EXEC, _FIXTURE_DYN])
def test_inject_blob_keeps_the_header_segment_clear_of_the_next_segment(fixture: Path, tmp_path: Path) -> None:
    # Growing that segment must never let it run into the one above it.
    target = _copy_fixture(fixture, tmp_path)

    _inject_into(target, _BLOB)

    loads = [entry for entry in program_headers(target) if entry.p_type == PT_LOAD]
    header_segment = next(entry for entry in loads if entry.p_offset == 0)
    above = [entry.p_vaddr for entry in loads if entry.p_vaddr > header_segment.p_vaddr]
    assert header_segment.p_vaddr + header_segment.p_memsz <= min(above)


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


@pytest.mark.parametrize("fixture", [_FIXTURE_EXEC, _FIXTURE_DYN])
def test_inject_blob_output_satisfies_every_strict_loader_invariant(fixture: Path, tmp_path: Path) -> None:
    # The assertions above each pin one field the injector writes. This one pins the
    # whole shape of the produced image against the rules a strict loader checks
    # before it maps anything - the class of defect that emulation and the kernel
    # both wave through, and that a container run is otherwise the only way to see.
    target = _copy_fixture(fixture, tmp_path)

    _inject_into(target, _BLOB)

    assert_loadable(target)


def test_loader_invariants_reject_a_header_segment_shorter_than_the_program_header_table(tmp_path: Path) -> None:
    # Proof that the oracle bites, on the exact defect that shipped: the injector adds
    # a program header, so the prefix a loader must find mapped grows, and an image
    # whose header segment stayed short of it is refused. Shrinking p_filesz by one
    # byte below the prefix is the smallest form of that image.
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    _inject_into(target, _BLOB)
    index = _header_segment_index(target)
    prefix_size = ELF64_HEADER_SIZE + len(program_headers(target)) * _PHDR_ENTRY_SIZE
    _overwrite_program_header(target, index, replace(program_headers(target)[index], p_filesz=prefix_size - 1))

    violations = load_invariant_violations(target)

    assert any(violation.startswith(HEADER_SEGMENT_SPAN) for violation in violations)


def test_loader_invariants_reject_a_load_segment_covering_another_segments_addresses(tmp_path: Path) -> None:
    # The other shipped defect: a segment whose address range claims memory another
    # PT_LOAD already owns, which aliases unrelated file bytes into the image. Here
    # the header segment is stretched over the appended one to reproduce that shape
    # without disturbing any other field the oracle looks at.
    target = _copy_fixture(_FIXTURE_DYN, tmp_path)
    _inject_into(target, _BLOB)
    index = _header_segment_index(target)
    header_segment, appended = program_headers(target)[index], program_headers(target)[-1]
    swallowing = appended.p_vaddr + appended.p_memsz - header_segment.p_vaddr
    _overwrite_program_header(target, index, replace(header_segment, p_memsz=swallowing))

    violations = load_invariant_violations(target)

    assert any(violation.startswith(LOAD_VADDR_OVERLAP) for violation in violations)
