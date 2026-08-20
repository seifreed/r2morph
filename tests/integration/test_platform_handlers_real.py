from pathlib import Path

from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect


def test_elf_handler_real_binary():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    handler = ELFHandler(binary_path)

    expect(handler.is_elf())
    expect(not (handler.validate() not in {True, False}))

    sections = handler.get_sections()
    expect(isinstance(sections, list))

    segments = handler.get_segments()
    expect(isinstance(segments, list))

    entry = handler.get_entry_point()
    expect(entry is None or isinstance(entry, int))

    arch = handler.get_architecture()
    expect(isinstance(arch, dict))

    cave = handler.find_code_cave(min_size=16)
    expect(cave is None or isinstance(cave, int))


def test_macho_handler_real_binary():
    binary_path = Path("fixtures/dataset/macho_arm64")
    handler = MachOHandler(binary_path)

    expect(handler.is_macho())
    expect(not (handler.validate() not in {True, False}))

    commands = handler.get_load_commands()
    expect(isinstance(commands, list))

    segments = handler.get_segments()
    expect(isinstance(segments, list))

    integrity_ok, reason = handler.validate_integrity()
    expect(isinstance(integrity_ok, bool))
    expect(isinstance(reason, str))

    is_fat = handler.is_fat_binary()
    expect(isinstance(is_fat, bool))


def test_pe_handler_real_binary():
    binary_path = Path("fixtures/dataset/pe_x86_64.exe")
    handler = PEHandler(binary_path)

    expect(handler.is_pe())
    expect(not (handler.validate() not in {True, False}))

    sections = handler.get_sections()
    expect(isinstance(sections, list))

    imports = handler.get_imports()
    expect(isinstance(imports, list))
