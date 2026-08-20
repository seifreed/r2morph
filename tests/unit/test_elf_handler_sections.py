"""Characterization of ELFHandler.get_sections on a real 64-bit ELF.

Pins the section-header parse end-to-end against fixtures/dataset/elf_x86_64 (a real,
statically-linked x86-64 binary) so the per-entry struct unpacking can be
refactored without changing observable output. No mocks (CLAUDE.md sec.4):
the real handler parses a real on-disk binary.
"""

from pathlib import Path

from r2morph.platform.elf_handler import ELFHandler
from tests.utils.assertions import expect

_EXPECTED_FIRST_LOAD_ALIGN_4096 = 4096
_EXPECTED_FIRST_LOAD_FILESZ_288 = 288
_EXPECTED_FIRST_LOAD_FLAGS_4 = 4
_EXPECTED_FIRST_LOAD_VADDR_2097152 = 0x200000
_EXPECTED_TEXT_ALIGN_4 = 4
_EXPECTED_TEXT_SIZE_12 = 12
_EXPECTED_TEXT_VADDR_2101536 = 0x201120


_EXPECTED_SECTION_KEYS = {
    "name",
    "vaddr",
    "size",
    "offset",
    "flags",
    "type",
    "link",
    "info",
    "align",
    "entsize",
    "index",
}


def test_get_sections_parses_real_elf64() -> None:
    handler = ELFHandler(Path("fixtures/dataset/elf_x86_64"))

    sections = handler.get_sections()

    names = [section["name"] for section in sections]
    expect(not (".text" not in names))
    expect(not (".symtab" not in names))
    expect(not (".shstrtab" not in names))

    for section in sections:
        expect(set(section.keys()) == _EXPECTED_SECTION_KEYS)

    text = next(section for section in sections if section["name"] == ".text")
    expect(text["vaddr"] == _EXPECTED_TEXT_VADDR_2101536)
    expect(text["size"] == _EXPECTED_TEXT_SIZE_12)
    expect(text["type"] == 1)
    expect(text["align"] == _EXPECTED_TEXT_ALIGN_4)
    expect(text["index"] == 1)


_EXPECTED_SEGMENT_KEYS = {
    "type",
    "type_name",
    "vaddr",
    "paddr",
    "filesz",
    "memsz",
    "offset",
    "flags",
    "align",
    "index",
}


def test_get_segments_parses_real_elf64() -> None:
    handler = ELFHandler(Path("fixtures/dataset/elf_x86_64"))

    segments = handler.get_segments()

    expect([segment["type_name"] for segment in segments] == ["PHDR", "LOAD", "LOAD", "GNU_STACK"])

    for segment in segments:
        expect(set(segment.keys()) == _EXPECTED_SEGMENT_KEYS)

    # The first LOAD pins the 64-bit field order, including p_flags (which the
    # ELF spec moves relative to the 32-bit layout).
    first_load = next(segment for segment in segments if segment["type_name"] == "LOAD")
    expect(first_load["vaddr"] == _EXPECTED_FIRST_LOAD_VADDR_2097152)
    expect(first_load["filesz"] == _EXPECTED_FIRST_LOAD_FILESZ_288)
    expect(first_load["flags"] == _EXPECTED_FIRST_LOAD_FLAGS_4)
    expect(first_load["align"] == _EXPECTED_FIRST_LOAD_ALIGN_4096)
