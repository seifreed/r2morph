from pathlib import Path
import shutil

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import BinaryRewriter, RewriteOperation


def test_binary_rewriter_real_rewrite(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "rewrite_target"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        bin_obj.filepath = str(temp_binary)

        funcs = bin_obj.get_functions()
        if not funcs:
            pytest.skip("No functions found for patching")

        addr = funcs[0].get("offset", funcs[0].get("addr", 0))
        instructions = bin_obj.get_function_disasm(addr)
        if not instructions:
            pytest.skip("No instructions found for patching")

        patch_addr = instructions[0].get("addr", 0)
        if patch_addr == 0:
            pytest.skip("Invalid patch address")

        rewriter = BinaryRewriter(bin_obj)
        added = rewriter.add_patch(patch_addr, ["nop"], RewriteOperation.INSTRUCTION_REPLACE)
        assert added is True

        output_path = tmp_path / "rewritten.bin"
        result = rewriter.rewrite_binary(str(output_path), preserve_original=False)

    assert result.success is True
    assert output_path.exists()


def test_binary_rewriter_no_binary_error():
    rewriter = BinaryRewriter(binary=None)
    result = rewriter.rewrite_binary("out.bin", preserve_original=False)
    assert result.success is False
