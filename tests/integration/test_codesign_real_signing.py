from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.platform.codesign import CodeSigner


def test_codesign_roundtrip_on_macho(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("Codesign test requires macOS")

    macho_path = Path("dataset/macho_arm64")
    if not macho_path.exists():
        pytest.skip("Mach-O test binary not available")

    work_path = tmp_path / "codesign_sample"
    work_path.write_bytes(macho_path.read_bytes())

    signer = CodeSigner()
    assert signer.sign_binary(work_path, adhoc=True) is True
    assert signer.verify(work_path) is True
