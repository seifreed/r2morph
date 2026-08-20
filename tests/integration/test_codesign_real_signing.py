from __future__ import annotations

import platform
from pathlib import Path

import pytest

from r2morph.platform.codesign import CodeSigner
from tests.utils.assertions import expect


def test_codesign_roundtrip_on_macho(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("Codesign test requires macOS")

    macho_path = Path("fixtures/dataset/macho_arm64")
    if not macho_path.exists():
        pytest.skip("Mach-O test binary not available")

    work_path = tmp_path / "codesign_sample"
    work_path.write_bytes(macho_path.read_bytes())

    signer = CodeSigner()
    expect(not (signer.sign(work_path, adhoc=True) is not True))
    expect(not (signer.verify(work_path) is not True))
