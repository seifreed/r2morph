from pathlib import Path
import shutil

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.register_substitution import RegisterSubstitutionPass


def test_register_substitution_arm64_skip(tmp_path: Path):
    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "arm64_reg_sub"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = RegisterSubstitutionPass(config={"probability": 1.0})
        result = pass_obj.apply(bin_obj)

    assert result.get("skipped") is True
    assert result.get("mutations_applied") == 0
