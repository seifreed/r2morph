import platform
from pathlib import Path

import pytest

from r2morph.platform.macho_handler import MachOHandler
from r2morph.platform.codesign import CodeSigner


def test_macho_handler_basic_integrity(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("Mach-O integrity requires macOS tools")
    macho_path = Path("dataset/macho_arm64")
    if not macho_path.exists():
        pytest.skip("Mach-O binary not available")

    handler = MachOHandler(macho_path)
    assert handler.is_macho() is True

    commands = handler.get_load_commands()
    segments = handler.get_segments()
    assert isinstance(commands, list)
    assert isinstance(segments, list)

    ok, msg = handler.validate_integrity()
    assert isinstance(ok, bool)
    assert isinstance(msg, str)

    assert handler.is_fat_binary() is False

    thin_out = tmp_path / "thin_macho"
    extract_result = handler.extract_architecture("arm64", thin_out)
    assert isinstance(extract_result, bool)
    if extract_result:
        assert thin_out.exists()


def test_codesigner_adhoc_missing_identity():
    signer = CodeSigner()
    dummy_path = Path("dataset/macho_arm64")
    if not dummy_path.exists():
        pytest.skip("Mach-O binary not available")

    result = signer.sign(dummy_path, identity=None, adhoc=False)

    if platform.system() == "Darwin":
        assert result is False
    elif platform.system() == "Windows":
        assert result is False
    else:
        assert result is True
