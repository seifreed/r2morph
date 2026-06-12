"""Characterization of ELFHandler.get_sections on a real 64-bit ELF.

Pins the section-header parse end-to-end against dataset/elf_x86_64 (a real,
statically-linked x86-64 binary) so the per-entry struct unpacking can be
refactored without changing observable output. No mocks (CLAUDE.md sec.4):
the real handler parses a real on-disk binary.
"""

from pathlib import Path

from r2morph.platform.elf_handler import ELFHandler

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
    handler = ELFHandler(Path("dataset/elf_x86_64"))

    sections = handler.get_sections()

    names = [section["name"] for section in sections]
    assert ".text" in names
    assert ".symtab" in names
    assert ".shstrtab" in names

    for section in sections:
        assert set(section.keys()) == _EXPECTED_SECTION_KEYS

    text = next(section for section in sections if section["name"] == ".text")
    assert text["vaddr"] == 0x201120
    assert text["size"] == 12
    assert text["type"] == 1  # SHT_PROGBITS
    assert text["align"] == 4
    assert text["index"] == 1


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
    handler = ELFHandler(Path("dataset/elf_x86_64"))

    segments = handler.get_segments()

    assert [segment["type_name"] for segment in segments] == ["PHDR", "LOAD", "LOAD", "GNU_STACK"]

    for segment in segments:
        assert set(segment.keys()) == _EXPECTED_SEGMENT_KEYS

    # The first LOAD pins the 64-bit field order, including p_flags (which the
    # ELF spec moves relative to the 32-bit layout).
    first_load = next(segment for segment in segments if segment["type_name"] == "LOAD")
    assert first_load["vaddr"] == 0x200000
    assert first_load["filesz"] == 288
    assert first_load["flags"] == 4
    assert first_load["align"] == 4096
