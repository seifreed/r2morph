from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler


def test_elf_handler_parses_real_binary() -> None:
    elf_path = Path("dataset/elf_x86_64")
    if not elf_path.exists():
        pytest.skip("ELF test binary not available")

    handler = ELFHandler(elf_path)
    assert handler.is_elf() is True
    assert handler.validate() is True

    sections = handler.get_sections()
    assert sections

    entry = handler.get_entry_point()
    assert isinstance(entry, int)
    assert entry > 0

    arch = handler.get_architecture()
    assert arch["bits"] in (32, 64)
    assert arch["machine_name"]


def test_macho_handler_parses_real_binary() -> None:
    macho_path = Path("dataset/macho_arm64")
    if not macho_path.exists():
        pytest.skip("Mach-O test binary not available")

    handler = MachOHandler(macho_path)
    assert handler.is_macho() is True
    assert handler.validate() is True

    load_cmds = handler.get_load_commands()
    segments = handler.get_segments()
    if handler._parse_lief() is None:
        assert isinstance(load_cmds, list)
        assert isinstance(segments, list)
    else:
        assert load_cmds
        assert segments

    ok, message = handler.validate_integrity()
    assert ok is True
    assert isinstance(message, str)

    assert handler.is_fat_binary() is False


def test_pe_handler_parses_real_binary(tmp_path: Path) -> None:
    pe_path = Path("dataset/pe_x86_64.exe")
    if not pe_path.exists():
        pytest.skip("PE test binary not available")

    work_path = tmp_path / "pe_sample.exe"
    work_path.write_bytes(pe_path.read_bytes())

    handler = PEHandler(work_path)
    assert handler.is_pe() is True
    assert handler.validate() is True

    sections = handler.get_sections()
    if handler._parse_lief() is None:
        assert isinstance(sections, list)
    else:
        assert sections

    assert handler.fix_checksum() is True
