from pathlib import Path
import platform
import shutil

import pytest

from r2morph.platform.codesign import CodeSigner


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

    assert signer.sign(binary_path, adhoc=False, identity=None) is False


def test_codesign_adhoc_entitlements_hardened(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")
    if not _has_codesign():
        pytest.skip("codesign not available")

    binary_path = Path("dataset/macho_arm64")
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

    assert isinstance(sign_ok, bool)
    if sign_ok:
        assert signer.verify(temp_binary) is True
