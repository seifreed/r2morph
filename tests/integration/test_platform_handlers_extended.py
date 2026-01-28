from pathlib import Path

import pytest

from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler


def test_elf_handler_extended():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    handler = ELFHandler(binary_path)
    assert handler.is_elf() is True
    assert handler.validate() is True

    sections = handler.get_sections()
    assert isinstance(sections, list)
    assert sections

    segments = handler.get_segments()
    assert isinstance(segments, list)

    symbols = handler.get_symbol_tables()
    assert isinstance(symbols, dict)

    entry = handler.get_entry_point()
    assert entry is None or isinstance(entry, int)

    arch = handler.get_architecture()
    assert "bits" in arch

    cave = handler.find_code_cave(min_size=32)
    assert cave is None or isinstance(cave, int)


def test_pe_handler_extended():
    binary_path = Path("dataset/pe_x86_64.exe")
    if not binary_path.exists():
        pytest.skip("PE binary not available")

    handler = PEHandler(binary_path)
    assert handler.is_pe() is True

    sections = handler.get_sections()
    assert isinstance(sections, list)

    imports = handler.get_imports()
    assert isinstance(imports, list)

    checksum = handler._calculate_checksum()
    assert isinstance(checksum, int)

    assert handler.fix_checksum() in {True, False}
    assert handler.validate() in {True, False}


def test_macho_handler_extended():
    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    handler = MachOHandler(binary_path)
    assert handler.is_macho() is True

    commands = handler.get_load_commands()
    assert isinstance(commands, list)

    segments = handler.get_segments()
    assert isinstance(segments, list)

    assert handler.validate() in {True, False}
    valid, reason = handler.validate_integrity()
    assert isinstance(valid, bool)
    assert isinstance(reason, str)

    assert handler.is_fat_binary() in {True, False}
