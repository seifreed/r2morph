from pathlib import Path
import shutil

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass


def test_dead_code_injection_with_padding(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "dead_code_padding"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = DeadCodeInjectionPass(
            config={
                "max_injections_per_function": 1,
                "probability": 1.0,
                "min_padding_size": 4,
                "code_complexity": "simple",
            }
        )

        functions = bin_obj.get_functions()
        if not functions:
            pytest.skip("No functions found")

        addr = functions[0].get("offset", functions[0].get("addr", 0))
        if not addr:
            pytest.skip("No valid function address")

        # Create padding so injection points exist
        bin_obj.nop_fill(addr, 12)

        result = pass_obj.apply(bin_obj)
        assert "mutations_applied" in result
