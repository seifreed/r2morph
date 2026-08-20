from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect


def test_macho_handler_basic_operations() -> None:
    macho_path = Path("fixtures/dataset/macho_arm64")
    if not macho_path.exists():
        pytest.skip("Mach-O test binary not available")

    handler = MachOHandler(macho_path)
    expect(not (handler.is_macho() is not True))
    expect(not (handler.is_fat_binary() is not False))
    expect(not (handler.validate() is not True))

    commands = handler.get_load_commands()
    segments = handler.get_segments()
    expect(isinstance(commands, list))
    expect(isinstance(segments, list))

    ok, _ = handler.validate_integrity()
    expect(not (ok is not True))


def test_pe_handler_checksum_and_validation(tmp_path: Path) -> None:
    pe_path = Path("fixtures/dataset/pe_x86_64.exe")
    if not pe_path.exists():
        pytest.skip("PE test binary not available")

    work_path = tmp_path / "sample.exe"
    shutil.copyfile(pe_path, work_path)

    handler = PEHandler(work_path)
    expect(not (handler.is_pe() is not True))
    expect(not (handler.validate() is not True))

    checksum = handler._calculate_checksum()
    expect(isinstance(checksum, int))

    expect(not (handler.fix_checksum() is not True))
    new_section_vaddr = handler.add_section("test", 128)
    expect(isinstance(new_section_vaddr, int))
    expect(not (new_section_vaddr <= 0))

    sections = handler.get_sections()
    imports = handler.get_imports()
    expect(isinstance(sections, list))
    expect(isinstance(imports, list))
