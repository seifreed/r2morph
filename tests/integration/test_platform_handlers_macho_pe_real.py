from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler


def test_macho_handler_basic_operations() -> None:
    macho_path = Path("dataset/macho_arm64")
    if not macho_path.exists():
        pytest.skip("Mach-O test binary not available")

    handler = MachOHandler(macho_path)
    assert handler.is_macho() is True
    assert handler.is_fat_binary() is False
    assert handler.validate() is True

    commands = handler.get_load_commands()
    segments = handler.get_segments()
    assert isinstance(commands, list)
    assert isinstance(segments, list)

    ok, _ = handler.validate_integrity()
    assert ok is True


def test_pe_handler_checksum_and_validation(tmp_path: Path) -> None:
    pe_path = Path("dataset/pe_x86_64.exe")
    if not pe_path.exists():
        pytest.skip("PE test binary not available")

    work_path = tmp_path / "sample.exe"
    shutil.copyfile(pe_path, work_path)

    handler = PEHandler(work_path)
    assert handler.is_pe() is True
    assert handler.validate() is True

    checksum = handler._calculate_checksum()
    assert isinstance(checksum, int)

    assert handler.fix_checksum() is True
    assert handler.add_section("test", 128) is None

    sections = handler.get_sections()
    imports = handler.get_imports()
    assert isinstance(sections, list)
    assert isinstance(imports, list)
