from pathlib import Path

from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler


def test_elf_handler_real_binary():
    binary_path = Path("dataset/elf_x86_64")
    handler = ELFHandler(binary_path)

    assert handler.is_elf()
    assert handler.validate() in {True, False}

    sections = handler.get_sections()
    assert isinstance(sections, list)

    segments = handler.get_segments()
    assert isinstance(segments, list)

    entry = handler.get_entry_point()
    assert entry is None or isinstance(entry, int)

    arch = handler.get_architecture()
    assert isinstance(arch, dict)

    cave = handler.find_code_cave(min_size=16)
    assert cave is None or isinstance(cave, int)


def test_macho_handler_real_binary():
    binary_path = Path("dataset/macho_arm64")
    handler = MachOHandler(binary_path)

    assert handler.is_macho()
    assert handler.validate() in {True, False}

    commands = handler.get_load_commands()
    assert isinstance(commands, list)

    segments = handler.get_segments()
    assert isinstance(segments, list)

    integrity_ok, reason = handler.validate_integrity()
    assert isinstance(integrity_ok, bool)
    assert isinstance(reason, str)

    is_fat = handler.is_fat_binary()
    assert isinstance(is_fat, bool)


def test_pe_handler_real_binary():
    binary_path = Path("dataset/pe_x86_64.exe")
    handler = PEHandler(binary_path)

    assert handler.is_pe()
    assert handler.validate() in {True, False}

    sections = handler.get_sections()
    assert isinstance(sections, list)

    imports = handler.get_imports()
    assert isinstance(imports, list)
