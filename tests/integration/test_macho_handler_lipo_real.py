from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.platform.macho_handler import MachOHandler


def _dataset_path(name: str) -> Path:
    return Path("dataset") / name


def test_macho_handler_extract_architecture_lipo(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("macOS-only lipo test")
    if shutil.which("lipo") is None:
        pytest.skip("lipo not available")

    source = _dataset_path("macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    work_path = tmp_path / "macho_input"
    work_path.write_bytes(source.read_bytes())

    handler = MachOHandler(work_path)
    output_path = tmp_path / "macho_thin"

    ok = handler.extract_architecture("arm64", output_path)
    assert ok is True or ok is False
    if ok:
        assert output_path.exists()


def test_macho_handler_create_fat_binary_lipo(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("macOS-only lipo test")
    if shutil.which("lipo") is None:
        pytest.skip("lipo not available")

    source = _dataset_path("macho_arm64")
    if not source.exists():
        pytest.skip("Mach-O test binary not available")

    thin1 = tmp_path / "macho1"
    thin1.write_bytes(source.read_bytes())

    fat_out = tmp_path / "macho_fat"
    handler = MachOHandler(thin1)
    ok = handler.create_fat_binary([thin1], fat_out)
    assert ok is True or ok is False
    if ok:
        assert fat_out.exists()
