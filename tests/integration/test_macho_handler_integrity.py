import platform
from pathlib import Path

import pytest

from r2morph.platform.codesign import CodeSigner
from r2morph.platform.macho_handler import MachOHandler
from tests.utils.assertions import expect


def test_macho_handler_basic_integrity(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("Mach-O integrity requires macOS tools")
    macho_path = Path("fixtures/dataset/macho_arm64")
    if not macho_path.exists():
        pytest.skip("Mach-O binary not available")

    handler = MachOHandler(macho_path)
    expect(not (handler.is_macho() is not True))

    commands = handler.get_load_commands()
    segments = handler.get_segments()
    expect(isinstance(commands, list))
    expect(isinstance(segments, list))

    ok, msg = handler.validate_integrity()
    expect(isinstance(ok, bool))
    expect(isinstance(msg, str))

    expect(not (handler.is_fat_binary() is not False))

    thin_out = tmp_path / "thin_macho"
    extract_result = handler.extract_architecture("arm64", thin_out)
    expect(isinstance(extract_result, bool))
    expect(not (extract_result and not (thin_out.exists())))


def test_codesigner_adhoc_missing_identity():
    signer = CodeSigner()
    dummy_path = Path("fixtures/dataset/macho_arm64")
    if not dummy_path.exists():
        pytest.skip("Mach-O binary not available")

    result = signer.sign(dummy_path, identity=None, adhoc=False)

    if platform.system() == "Darwin" or platform.system() == "Windows":
        expect(not (result is not False))
    else:
        expect(not (result is not True))
