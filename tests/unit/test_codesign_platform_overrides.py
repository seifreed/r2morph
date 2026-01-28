from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.platform.codesign import CodeSigner


def test_codesign_windows_sign_missing_identity(tmp_path: Path) -> None:
    signer = CodeSigner()
    signer.platform = "Windows"

    binary_path = tmp_path / "dummy.exe"
    binary_path.write_bytes(b"MZ")

    assert signer.sign(binary_path, identity=None) is False


def test_codesign_linux_noop_paths(tmp_path: Path) -> None:
    signer = CodeSigner()
    signer.platform = "Linux"

    binary_path = tmp_path / "dummy.bin"
    binary_path.write_bytes(b"\x7fELF")

    assert signer.sign(binary_path) is True
    assert signer.verify(binary_path) is True
    assert signer.needs_signing(binary_path) is False
