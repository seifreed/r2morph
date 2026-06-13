"""Characterization of ELFHandler._parse_elf_header on a real 64-bit ELF.

Pins the exact parsed header dict against dataset/elf_x86_64 so the 64/32-bit
header parsing can be de-duplicated without changing observable output. No
mocks (CLAUDE.md sec.4): a real handler parses a real on-disk binary.
"""

from pathlib import Path

from r2morph.platform.elf_handler import ELFHandler


def test_parse_elf_header_exact_real_elf64() -> None:
    handler = ELFHandler(Path("dataset/elf_x86_64"))

    header = handler._parse_elf_header()

    assert header == {
        "e_ident": b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "e_type": 2,
        "e_machine": 62,
        "e_version": 1,
        "e_entry": 2101536,
        "e_phoff": 64,
        "e_shoff": 432,
        "e_flags": 0,
        "e_ehsize": 64,
        "e_phentsize": 56,
        "e_phnum": 4,
        "e_shentsize": 64,
        "e_shnum": 6,
        "e_shstrndx": 4,
        "is_64bit": True,
        "is_little_endian": True,
    }
    # instance flags set as a side effect
    assert handler._is_64bit is True
    assert handler._is_little_endian is True


def test_parse_elf_header_is_cached() -> None:
    handler = ELFHandler(Path("dataset/elf_x86_64"))
    assert handler._parse_elf_header() is handler._parse_elf_header()
