from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass


def test_dead_code_injection_point_detection():
    pass_obj = DeadCodeInjectionPass(config={"min_padding_size": 2})
    instructions = [
        {"offset": 0x1000, "size": 1, "mnemonic": "nop"},
        {"offset": 0x1001, "size": 1, "mnemonic": "nop"},
        {"offset": 0x1002, "size": 1, "mnemonic": "mov"},
        {"offset": 0x1003, "size": 1, "mnemonic": "int3"},
        {"offset": 0x1004, "size": 1, "mnemonic": "int3"},
    ]

    points = pass_obj._find_injection_points(instructions)
    assert points
    assert any(p["type"] == "padding" for p in points)

    assert pass_obj._is_safe_injection_point(instructions[0], instructions, 0) is True
    assert pass_obj._is_safe_injection_point(instructions[2], instructions, 2) is False


def test_dead_code_generation_for_size(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        pass_obj = DeadCodeInjectionPass(config={"code_complexity": "simple"})
        dead_code = pass_obj._generate_dead_code_for_size(bin_obj, 5, 0)

    assert dead_code is not None
    assert len(dead_code) == 5
