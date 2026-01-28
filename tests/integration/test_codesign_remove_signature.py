from pathlib import Path
import platform
import shutil

import pytest

from r2morph.platform.codesign import CodeSigner


def test_codesign_remove_signature(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("macOS-only test")

    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "codesign_remove"
    shutil.copy(binary_path, temp_binary)

    signer = CodeSigner()
    removed = signer.remove_signature(temp_binary)
    assert isinstance(removed, bool)
