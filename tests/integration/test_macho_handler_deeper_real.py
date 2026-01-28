from pathlib import Path
import platform
import shutil

import pytest

from r2morph.platform.macho_handler import MachOHandler


def _has_lipo() -> bool:
    return shutil.which("lipo") is not None


def test_macho_handler_basic_properties():
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")

    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    handler = MachOHandler(binary_path)
    assert handler.is_macho() is True
    assert handler.is_fat_binary() is False
    assert handler.validate() is True

    ok, msg = handler.validate_integrity()
    assert isinstance(ok, bool)
    assert isinstance(msg, str)

    commands = handler.get_load_commands()
    segments = handler.get_segments()
    assert isinstance(commands, list)
    assert isinstance(segments, list)

    parsed = handler._parse_lief()
    if parsed is not None:
        assert len(segments) > 0
        assert len(commands) > 0


def test_macho_handler_lipo_fallbacks(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")
    if not _has_lipo():
        pytest.skip("lipo not available")

    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    handler = MachOHandler(binary_path)
    output_path = tmp_path / "thin_arm64"
    extract_ok = handler.extract_architecture("arm64", output_path)
    assert isinstance(extract_ok, bool)
    if extract_ok:
        assert output_path.exists()

    fat_output = tmp_path / "fat_binary"
    create_ok = handler.create_fat_binary([], fat_output)
    assert isinstance(create_ok, bool)
