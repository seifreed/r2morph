import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from tests.utils.assertions import expect


def test_instruction_expansion_unsupported_arch(tmp_path: Path):
    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "arm64_inst_expand"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = InstructionExpansionPass(config={"probability": 1.0})
        result = pass_obj.apply(bin_obj)

    expect("error" not in result)
    expect(not (result.get("total_functions", 0) < 1))
    expect(not (result.get("mutations_applied", 0) < 0))
