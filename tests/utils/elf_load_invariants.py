"""
Structural invariants a strict ELF64 loader enforces before it maps an image.

Emulators and the Linux kernel are forgiving: both accept program headers that a
conformant loader rejects, so an image can execute to the right exit status and
still be malformed. Two such images shipped from the segment injector - one that
aliased unrelated file bytes into the address space, and one whose ELF-header
segment stopped short of the program-header table it had just grown - and neither
was visible to emulation. This module is the oracle that sees them.

It parses the produced bytes with ``struct`` alone, so it is independent of the
code that wrote them and of every third-party library: any test, unit or
integration, can hold an injector result up against it without a container.

Each check yields a message opening with the module-level constant naming the
invariant, so a failure identifies which rule broke, on which segment, and with
which values - and so a test can assert that a specific invariant is the one that
fired.
"""

from __future__ import annotations

import itertools
import struct
from dataclasses import dataclass
from pathlib import Path

ELF64_HEADER_SIZE = 0x40
# p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align.
PHDR_FORMAT = "<IIQQQQQQ"
PHDR_ENTRY_SIZE = struct.calcsize(PHDR_FORMAT)
PT_LOAD = 1
PT_PHDR = 6

HEADER_SEGMENT_SPAN = "load segment mapping the ELF header does not span the program-header table"
OFFSET_VADDR_CONGRUENCE = "PT_LOAD file offset and virtual address are incongruent modulo p_align"
LOAD_VADDR_OVERLAP = "two PT_LOAD virtual address ranges overlap"
PHOFF_NOT_MAPPED = "e_phoff is not inside any PT_LOAD file range"
PT_PHDR_NOT_COVERED = "PT_PHDR is not covered by any PT_LOAD"
PT_PHDR_OFFSET_DISAGREES = "PT_PHDR p_offset disagrees with e_phoff"
FILESZ_EXCEEDS_MEMSZ = "segment p_filesz exceeds its p_memsz"
SEGMENT_PAST_END_OF_FILE = "segment file range runs past the end of the file"

_ELF_MAGIC = b"\x7fELF"
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_E_PHOFF = 0x20
_E_EHSIZE = 0x34
_E_PHENTSIZE = 0x36
_E_PHNUM = 0x38


@dataclass(frozen=True)
class ProgramHeader:
    """One ELF64 program-header entry, re-parsed from a produced file."""

    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int


@dataclass(frozen=True)
class Elf64Image:
    """The header fields and program-header table a loader reads before mapping."""

    file_size: int
    e_phoff: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    headers: tuple[ProgramHeader, ...]

    @property
    def header_prefix_size(self) -> int:
        """Bytes of ELF header plus program-header table a loader must find mapped."""
        return self.e_ehsize + self.e_phnum * self.e_phentsize

    @property
    def table_end(self) -> int:
        """File offset one past the last program-header entry."""
        return self.e_phoff + self.e_phnum * self.e_phentsize


def read_elf64(path: Path) -> Elf64Image:
    """Parse a little-endian ELF64's header and program-header table."""
    raw = path.read_bytes()
    if raw[:4] != _ELF_MAGIC or raw[4] != _ELFCLASS64 or raw[5] != _ELFDATA2LSB:
        raise ValueError(f"{path} is not a little-endian ELF64 image")

    e_phoff = struct.unpack_from("<Q", raw, _E_PHOFF)[0]
    e_ehsize = struct.unpack_from("<H", raw, _E_EHSIZE)[0]
    e_phentsize = struct.unpack_from("<H", raw, _E_PHENTSIZE)[0]
    e_phnum = struct.unpack_from("<H", raw, _E_PHNUM)[0]
    headers = tuple(
        ProgramHeader(*struct.unpack_from(PHDR_FORMAT, raw, e_phoff + index * e_phentsize)) for index in range(e_phnum)
    )
    return Elf64Image(len(raw), e_phoff, e_ehsize, e_phentsize, e_phnum, headers)


def program_headers(path: Path) -> tuple[ProgramHeader, ...]:
    """A file's program-header table, straight from its bytes."""
    return read_elf64(path).headers


def _loads(image: Elf64Image) -> list[tuple[int, ProgramHeader]]:
    return [(index, header) for index, header in enumerate(image.headers) if header.p_type == PT_LOAD]


def _header_segment_span_violations(image: Elf64Image) -> list[str]:
    """The segment mapping offset 0 must cover the ELF header plus the whole table."""
    mapping_header = [(index, header) for index, header in _loads(image) if header.p_offset == 0]
    if not mapping_header:
        return [f"{HEADER_SEGMENT_SPAN}: no PT_LOAD starts at file offset 0, so the ELF header is never mapped"]
    return [
        f"{HEADER_SEGMENT_SPAN}: PT_LOAD #{index} p_filesz {header.p_filesz:#x} < {image.header_prefix_size:#x} "
        f"(e_ehsize {image.e_ehsize:#x} + e_phnum {image.e_phnum} * e_phentsize {image.e_phentsize:#x})"
        for index, header in mapping_header
        if header.p_filesz < image.header_prefix_size
    ]


def _congruence_violations(image: Elf64Image) -> list[str]:
    """``p_offset`` and ``p_vaddr`` must agree modulo ``p_align`` or the mapping shifts."""
    return [
        f"{OFFSET_VADDR_CONGRUENCE}: PT_LOAD #{index} p_offset {header.p_offset:#x} % {header.p_align:#x} "
        f"!= p_vaddr {header.p_vaddr:#x} % {header.p_align:#x}"
        for index, header in _loads(image)
        if header.p_align > 1 and header.p_offset % header.p_align != header.p_vaddr % header.p_align
    ]


def _overlap_violations(image: Elf64Image) -> list[str]:
    """No two loadable ranges may claim the same virtual address."""
    occupied = sorted((entry for entry in _loads(image) if entry[1].p_memsz), key=lambda entry: entry[1].p_vaddr)
    violations = []
    for (lower_index, lower), (upper_index, upper) in itertools.pairwise(occupied):
        if upper.p_vaddr < lower.p_vaddr + lower.p_memsz:
            violations.append(
                f"{LOAD_VADDR_OVERLAP}: PT_LOAD #{lower_index} "
                f"[{lower.p_vaddr:#x}, {lower.p_vaddr + lower.p_memsz:#x}) overlaps PT_LOAD #{upper_index} "
                f"[{upper.p_vaddr:#x}, {upper.p_vaddr + upper.p_memsz:#x})"
            )
    return violations


def _contains_file_range(container: ProgramHeader, start: int, end: int) -> bool:
    return container.p_offset <= start and end <= container.p_offset + container.p_filesz


def _phoff_violations(image: Elf64Image) -> list[str]:
    """The kernel derives ``AT_PHDR`` from the PT_LOAD holding ``e_phoff``."""
    if any(_contains_file_range(header, image.e_phoff, image.table_end) for _index, header in _loads(image)):
        return []
    return [
        f"{PHOFF_NOT_MAPPED}: the table at [{image.e_phoff:#x}, {image.table_end:#x}) "
        "lies outside every PT_LOAD file range"
    ]


def _pt_phdr_violations(image: Elf64Image) -> list[str]:
    """A declared PT_PHDR must be loadable and must describe the real table."""
    violations = []
    for index, header in enumerate(image.headers):
        if header.p_type != PT_PHDR:
            continue
        end = header.p_offset + header.p_filesz
        if not any(_contains_file_range(load, header.p_offset, end) for _load_index, load in _loads(image)):
            violations.append(
                f"{PT_PHDR_NOT_COVERED}: PT_PHDR #{index} file range [{header.p_offset:#x}, {end:#x}) "
                "is not contained in any PT_LOAD"
            )
        if header.p_offset != image.e_phoff:
            violations.append(
                f"{PT_PHDR_OFFSET_DISAGREES}: PT_PHDR #{index} p_offset {header.p_offset:#x} "
                f"!= e_phoff {image.e_phoff:#x}"
            )
    return violations


def _size_violations(image: Elf64Image) -> list[str]:
    """Every segment must fit in the file and never claim more bytes than memory."""
    violations = []
    for index, header in enumerate(image.headers):
        if header.p_filesz > header.p_memsz:
            violations.append(
                f"{FILESZ_EXCEEDS_MEMSZ}: segment #{index} p_filesz {header.p_filesz:#x} > p_memsz {header.p_memsz:#x}"
            )
        if header.p_offset + header.p_filesz > image.file_size:
            violations.append(
                f"{SEGMENT_PAST_END_OF_FILE}: segment #{index} ends at "
                f"{header.p_offset + header.p_filesz:#x}, past the {image.file_size:#x}-byte file"
            )
    return violations


def load_invariant_violations(path: Path) -> tuple[str, ...]:
    """Every loader invariant ``path`` breaks, each message naming the invariant."""
    image = read_elf64(path)
    violations: list[str] = []
    violations += _header_segment_span_violations(image)
    violations += _congruence_violations(image)
    violations += _overlap_violations(image)
    violations += _phoff_violations(image)
    violations += _pt_phdr_violations(image)
    violations += _size_violations(image)
    return tuple(violations)


def assert_loadable(path: Path) -> None:
    """Raise with every violation listed unless ``path`` satisfies all of them."""
    violations = load_invariant_violations(path)
    if violations:
        listed = "\n  ".join(violations)
        raise AssertionError(f"{path.name} violates ELF loader invariants:\n  {listed}")
