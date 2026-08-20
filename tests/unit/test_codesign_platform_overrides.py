from __future__ import annotations

from pathlib import Path

from r2morph.platform.codesign import CodeSigner
from tests.utils.assertions import expect


def test_codesign_windows_sign_missing_identity(tmp_path: Path) -> None:
    signer = CodeSigner()
    signer.platform = "Windows"

    binary_path = tmp_path / "dummy.exe"
    binary_path.write_bytes(b"MZ")

    expect(not (signer.sign(binary_path, identity=None) is not False))


def test_codesign_linux_noop_paths(tmp_path: Path) -> None:
    signer = CodeSigner()
    signer.platform = "Linux"

    binary_path = tmp_path / "dummy.bin"
    binary_path.write_bytes(b"\x7fELF")

    expect(not (signer.sign(binary_path) is not True))
    expect(not (signer.verify(binary_path) is not True))
    expect(not (signer.needs_signing(binary_path) is not False))
