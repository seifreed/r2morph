from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect


def test_elf_handler_parses_real_binary() -> None:
    elf_path = Path("fixtures/dataset/elf_x86_64")
    if not elf_path.exists():
        pytest.skip("ELF test binary not available")

    handler = ELFHandler(elf_path)
    expect(not (handler.is_elf() is not True))
    expect(not (handler.validate() is not True))

    sections = handler.get_sections()
    expect(sections)

    entry = handler.get_entry_point()
    expect(isinstance(entry, int))
    expect(not (entry <= 0))

    arch = handler.get_architecture()
    expect(not (arch["bits"] not in (32, 64)))
    expect(arch["machine_name"])


def test_macho_handler_parses_real_binary() -> None:
    macho_path = Path("fixtures/dataset/macho_arm64")
    if not macho_path.exists():
        pytest.skip("Mach-O test binary not available")

    handler = MachOHandler(macho_path)
    expect(not (handler.is_macho() is not True))
    expect(not (handler.validate() is not True))

    load_cmds = handler.get_load_commands()
    segments = handler.get_segments()
    if handler._parse_lief() is None:
        expect(isinstance(load_cmds, list))
        expect(isinstance(segments, list))
    else:
        expect(load_cmds)
        expect(segments)

    ok, message = handler.validate_integrity()
    expect(not (ok is not True))
    expect(isinstance(message, str))

    expect(not (handler.is_fat_binary() is not False))


def test_pe_handler_parses_real_binary(tmp_path: Path) -> None:
    pe_path = Path("fixtures/dataset/pe_x86_64.exe")
    if not pe_path.exists():
        pytest.skip("PE test binary not available")

    work_path = tmp_path / "pe_sample.exe"
    work_path.write_bytes(pe_path.read_bytes())

    handler = PEHandler(work_path)
    expect(not (handler.is_pe() is not True))
    expect(not (handler.validate() is not True))

    sections = handler.get_sections()
    if handler._parse_lief() is None:
        expect(isinstance(sections, list))
    expect(sections)

    expect(not (handler.fix_checksum() is not True))
