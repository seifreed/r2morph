from pathlib import Path

import pytest

from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect


def test_elf_handler_extended():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    handler = ELFHandler(binary_path)
    expect(not (handler.is_elf() is not True))
    expect(not (handler.validate() is not True))

    sections = handler.get_sections()
    expect(isinstance(sections, list))
    expect(sections)

    segments = handler.get_segments()
    expect(isinstance(segments, list))

    symbols = handler.get_symbol_tables()
    expect(isinstance(symbols, dict))

    entry = handler.get_entry_point()
    expect(entry is None or isinstance(entry, int))

    arch = handler.get_architecture()
    expect(not ("bits" not in arch))

    cave = handler.find_code_cave(min_size=32)
    expect(cave is None or isinstance(cave, int))


def test_pe_handler_extended():
    binary_path = Path("fixtures/dataset/pe_x86_64.exe")
    if not binary_path.exists():
        pytest.skip("PE binary not available")

    handler = PEHandler(binary_path)
    expect(not (handler.is_pe() is not True))

    sections = handler.get_sections()
    expect(isinstance(sections, list))

    imports = handler.get_imports()
    expect(isinstance(imports, list))

    checksum = handler._calculate_checksum()
    expect(isinstance(checksum, int))

    expect(not (handler.fix_checksum() not in {True, False}))
    expect(not (handler.validate() not in {True, False}))


def test_macho_handler_extended():
    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    handler = MachOHandler(binary_path)
    expect(not (handler.is_macho() is not True))

    commands = handler.get_load_commands()
    expect(isinstance(commands, list))

    segments = handler.get_segments()
    expect(isinstance(segments, list))

    expect(not (handler.validate() not in {True, False}))
    valid, reason = handler.validate_integrity()
    expect(isinstance(valid, bool))
    expect(isinstance(reason, str))

    expect(not (handler.is_fat_binary() not in {True, False}))
