from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.platform.codesign import CodeSigner
from r2morph.platform.elf_handler import ELFHandler, SHF_EXECINSTR
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler


def _dataset_path(name: str) -> Path:
    return Path("dataset") / name


def test_elf_handler_entrypoint_arch_and_cave(tmp_path: Path) -> None:
    source = _dataset_path("elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "elf_sample.bin"
    work_path.write_bytes(source.read_bytes())

    handler = ELFHandler(work_path)
    assert handler.is_elf() is True

    entry = handler.get_entry_point()
    assert isinstance(entry, int)
    assert entry > 0

    arch = handler.get_architecture()
    assert "machine_name" in arch
    assert "x86" in arch["machine_name"].lower()

    sections = handler.get_sections()
    exec_sections = [section for section in sections if section["flags"] & SHF_EXECINSTR]
    assert exec_sections, "Expected executable section"
    section = max(exec_sections, key=lambda item: item.get("size", 0))
    offset = section["offset"]
    fill_size = min(section.get("size", 0), 8)
    assert fill_size > 0

    with open(work_path, "r+b") as f:
        f.seek(offset)
        f.write(b"\x00" * fill_size)

    cave = handler.find_code_cave(min_size=fill_size)
    assert cave is not None


def test_elf_handler_segments_real() -> None:
    source = _dataset_path("elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    handler = ELFHandler(source)
    segments = handler.get_segments()
    assert isinstance(segments, list)
    assert segments, "Expected at least one segment"
    assert all("type" in segment for segment in segments)


def test_macho_handler_integrity_and_fat(tmp_path: Path) -> None:
    source = _dataset_path("macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    work_path = tmp_path / "macho_sample"
    work_path.write_bytes(source.read_bytes())

    handler = MachOHandler(work_path)
    assert handler.is_macho() is True
    assert handler.is_fat_binary() is False

    segments = handler.get_segments()
    assert isinstance(segments, list)
    assert segments

    load_cmds = handler.get_load_commands()
    assert isinstance(load_cmds, list)
    assert load_cmds

    assert handler.validate() is True
    ok, _ = handler.validate_integrity()
    assert ok is True


def test_macho_handler_repair_integrity_adhoc(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("macOS-only codesign test")

    source = _dataset_path("macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    work_path = tmp_path / "macho_repair"
    work_path.write_bytes(source.read_bytes())

    handler = MachOHandler(work_path)
    assert handler.repair_integrity(timestamp=False) is True


def test_pe_handler_checksum_and_imports(tmp_path: Path) -> None:
    source = _dataset_path("pe_x86_64.exe")
    if not source.exists():
        pytest.skip("PE test binary not available")

    work_path = tmp_path / "pe_sample.exe"
    work_path.write_bytes(source.read_bytes())

    handler = PEHandler(work_path)
    assert handler.is_pe() is True

    assert handler.fix_checksum() is True

    sections = handler.get_sections()
    assert isinstance(sections, list)

    imports = handler.get_imports()
    assert isinstance(imports, list)


def test_codesign_needs_signing_cycle(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("macOS-only codesign test")

    source = _dataset_path("macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    work_path = tmp_path / "macho_sign"
    work_path.write_bytes(source.read_bytes())

    signer = CodeSigner()
    assert signer.sign(work_path, adhoc=True, timestamp=False) is True
    assert signer.needs_signing(work_path) is False

    assert signer.sign(work_path, adhoc=False, identity=None) is False
