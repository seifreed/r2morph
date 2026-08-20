import platform
import shutil
from pathlib import Path

import pytest

from r2morph.platform.macho_handler import MachOHandler
from tests.utils.assertions import expect


def _has_lipo() -> bool:
    return shutil.which("lipo") is not None


def test_macho_handler_basic_properties():
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")

    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    handler = MachOHandler(binary_path)
    expect(not (handler.is_macho() is not True))
    expect(not (handler.is_fat_binary() is not False))
    expect(not (handler.validate() is not True))

    ok, msg = handler.validate_integrity()
    expect(isinstance(ok, bool))
    expect(isinstance(msg, str))

    commands = handler.get_load_commands()
    segments = handler.get_segments()
    expect(isinstance(commands, list))
    expect(isinstance(segments, list))

    parsed = handler._parse_lief()
    if parsed is not None:
        expect(not (len(segments) <= 0))
        expect(not (len(commands) <= 0))


def test_macho_handler_lipo_fallbacks(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")
    if not _has_lipo():
        pytest.skip("lipo not available")

    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    handler = MachOHandler(binary_path)
    output_path = tmp_path / "thin_arm64"
    extract_ok = handler.extract_architecture("arm64", output_path)
    expect(isinstance(extract_ok, bool))
    expect(not (extract_ok and not (output_path.exists())))

    fat_output = tmp_path / "fat_binary"
    create_ok = handler.create_fat_binary([], fat_output)
    expect(isinstance(create_ok, bool))
