from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.platform.codesign import CodeSigner
from r2morph.platform.elf_handler import SHF_EXECINSTR, ELFHandler
from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect


def _dataset_path(name: str) -> Path:
    return Path("fixtures/dataset") / name


def test_elf_handler_entrypoint_arch_and_cave(tmp_path: Path) -> None:
    source = _dataset_path("elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "elf_sample.bin"
    work_path.write_bytes(source.read_bytes())

    handler = ELFHandler(work_path)
    expect(not (handler.is_elf() is not True))

    entry = handler.get_entry_point()
    expect(isinstance(entry, int))
    expect(not (entry <= 0))

    arch = handler.get_architecture()
    expect(not ("machine_name" not in arch))
    expect(not ("x86" not in arch["machine_name"].lower()))

    sections = handler.get_sections()
    exec_sections = [section for section in sections if section["flags"] & SHF_EXECINSTR]
    expect(exec_sections, "Expected executable section")
    section = max(exec_sections, key=lambda item: item.get("size", 0))
    offset = section["offset"]
    fill_size = min(section.get("size", 0), 8)
    expect(not (fill_size <= 0))

    with open(work_path, "r+b") as f:
        f.seek(offset)
        f.write(b"\x00" * fill_size)

    cave = handler.find_code_cave(min_size=fill_size)
    expect(cave is not None)


def test_elf_handler_segments_real() -> None:
    source = _dataset_path("elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    handler = ELFHandler(source)
    segments = handler.get_segments()
    expect(isinstance(segments, list))
    expect(segments, "Expected at least one segment")
    expect(all("type" in segment for segment in segments))


def test_macho_handler_integrity_and_fat(tmp_path: Path) -> None:
    source = _dataset_path("macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    work_path = tmp_path / "macho_sample"
    work_path.write_bytes(source.read_bytes())

    handler = MachOHandler(work_path)
    expect(not (handler.is_macho() is not True))
    expect(not (handler.is_fat_binary() is not False))

    segments = handler.get_segments()
    expect(isinstance(segments, list))
    expect(segments)

    load_cmds = handler.get_load_commands()
    expect(isinstance(load_cmds, list))
    expect(load_cmds)

    expect(not (handler.validate() is not True))
    ok, _ = handler.validate_integrity()
    expect(not (ok is not True))


def test_macho_handler_repair_integrity_adhoc(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("macOS-only codesign test")

    source = _dataset_path("macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    work_path = tmp_path / "macho_repair"
    work_path.write_bytes(source.read_bytes())

    handler = MachOHandler(work_path)
    expect(not (handler.repair_integrity(timestamp=False) is not True))


def test_pe_handler_checksum_and_imports(tmp_path: Path) -> None:
    source = _dataset_path("pe_x86_64.exe")
    if not source.exists():
        pytest.skip("PE test binary not available")

    work_path = tmp_path / "pe_sample.exe"
    work_path.write_bytes(source.read_bytes())

    handler = PEHandler(work_path)
    expect(not (handler.is_pe() is not True))

    expect(not (handler.fix_checksum() is not True))

    sections = handler.get_sections()
    expect(isinstance(sections, list))

    imports = handler.get_imports()
    expect(isinstance(imports, list))


def test_codesign_needs_signing_cycle(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("macOS-only codesign test")

    source = _dataset_path("macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    work_path = tmp_path / "macho_sign"
    work_path.write_bytes(source.read_bytes())

    signer = CodeSigner()
    expect(not (signer.sign(work_path, adhoc=True, timestamp=False) is not True))
    expect(not (signer.needs_signing(work_path) is not False))

    expect(not (signer.sign(work_path, adhoc=False, identity=None) is not False))
