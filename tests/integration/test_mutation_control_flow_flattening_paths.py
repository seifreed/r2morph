from pathlib import Path
import shutil

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_control_flow_flattening_select_candidates():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        pass_obj = ControlFlowFlatteningPass(config={"min_blocks_required": 2})
        candidates = pass_obj._select_candidates(bin_obj, bin_obj.get_functions())

    assert isinstance(candidates, list)
    if candidates:
        assert "_block_count" in candidates[0]


def test_control_flow_flattening_obfuscate_jump_guard(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "cff_jump"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = ControlFlowFlatteningPass()

        # Guard paths: too small jump or missing disasm should be False
        small_jump = {"offset": 0x1000, "size": 2, "disasm": "jmp 0x1002"}
        assert pass_obj._obfuscate_jump(bin_obj, small_jump, {}, "x86", 64) is False

        no_disasm = {"offset": 0x1000, "size": 6, "disasm": ""}
        assert pass_obj._obfuscate_jump(bin_obj, no_disasm, {}, "x86", 64) is False

        bad_target = {"offset": 0x1000, "size": 6, "disasm": "jmp sym.func"}
        assert pass_obj._obfuscate_jump(bin_obj, bad_target, {}, "x86", 64) is False


def test_control_flow_flattening_dead_code_insert_guard(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "cff_dead_code"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = ControlFlowFlatteningPass()
        # Unsupported arch should fail fast
        assert pass_obj._insert_dead_code_with_predicate(bin_obj, 0x1000, 4, "mips", 32) is False
