from pathlib import Path
import platform
import shutil
import subprocess

import pytest

from r2morph.platform.codesign import CodeSigner


def _has_codesign():
    return shutil.which("codesign") is not None


def test_codesign_verify_and_needs_signing(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")
    if not _has_codesign():
        pytest.skip("codesign not available")

    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "codesign_target"
    shutil.copy(binary_path, temp_binary)

    signer = CodeSigner()
    verify_before = signer.verify(temp_binary)
    needs = signer.needs_signing(temp_binary)

    assert isinstance(verify_before, bool)
    assert isinstance(needs, bool)

    # Attempt ad-hoc sign; if it succeeds, verify should pass
    sign_ok = signer.sign(temp_binary, adhoc=True)
    if sign_ok:
        assert signer.verify(temp_binary) is True
