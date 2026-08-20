import platform
import shutil
from pathlib import Path

import pytest

from r2morph.platform.codesign import CodeSigner
from tests.utils.assertions import expect


def _has_codesign() -> bool:
    return shutil.which("codesign") is not None


def _write_entitlements(path: Path) -> None:
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        "<dict>\n"
        "</dict>\n"
        "</plist>\n"
    )


def test_codesign_non_adhoc_requires_identity(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")

    signer = CodeSigner()
    binary_path = tmp_path / "unsigned_target"
    binary_path.write_text("placeholder")

    expect(not (signer.sign(binary_path, adhoc=False, identity=None) is not False))


def test_codesign_adhoc_entitlements_hardened(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")
    if not _has_codesign():
        pytest.skip("codesign not available")

    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "codesign_entitlements"
    shutil.copy(binary_path, temp_binary)

    entitlements = tmp_path / "entitlements.plist"
    _write_entitlements(entitlements)

    signer = CodeSigner()
    sign_ok = signer.sign(
        temp_binary,
        adhoc=True,
        entitlements=entitlements,
        hardened=True,
        timestamp=False,
    )

    expect(isinstance(sign_ok, bool))
    expect(not (sign_ok and signer.verify(temp_binary) is not True))
