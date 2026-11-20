import platform
import shutil
import sys
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.binary_rewriter import BinaryRewriter, RewriteOperation
from tests.utils.assertions import expect
from tests.utils.process import run_command

_MINIMUM_PATCHABLE_INSTRUCTIONS = 2


def test_binary_rewriter_real_rewrite(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
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
        if len(instructions) < _MINIMUM_PATCHABLE_INSTRUCTIONS:
            pytest.skip("Fewer than two instructions found for patching")

        patch_addr = instructions[1].get("addr", 0)
        if patch_addr == 0:
            pytest.skip("Invalid patch address")

        rewriter = BinaryRewriter(bin_obj)
        added = rewriter.add_patch(patch_addr, ["xor edi, edi"], RewriteOperation.INSTRUCTION_REPLACE)
        expect(not (added is not True))
        original = temp_binary.read_bytes()
        patch = rewriter.patches[0]
        expect(len(patch.original_bytes) == len(patch.new_bytes))
        expect(patch.size_change == 0)
        patch_offset = rewriter._file_offset_for_patch(patch)
        expect(patch_offset is not None)

        output_path = tmp_path / "rewritten.bin"
        result = rewriter.rewrite_binary(str(output_path), preserve_original=False)

    expect(not (result.success is not True))
    expect(output_path.exists())
    expect(temp_binary.read_bytes() == original)
    expect(output_path.read_bytes() != original)
    expect(patch.new_bytes == b"\x31\xff\x90")
    expect(output_path.read_bytes()[patch_offset : patch_offset + len(patch.new_bytes)] == patch.new_bytes)
    with Binary(output_path) as rewritten:
        rewritten.analyze("aa")
        expect(rewritten.r2.cmdj("ij").get("bin", {}).get("class") == "ELF64")
    if sys.platform == "linux" and platform.machine().lower() in {"x86_64", "amd64"}:
        original_result = run_command([str(temp_binary)], capture_output=True, timeout=30)
        rewritten_result = run_command([str(output_path)], capture_output=True, timeout=30)
        expect(
            (original_result.returncode, original_result.stdout, original_result.stderr)
            == (rewritten_result.returncode, rewritten_result.stdout, rewritten_result.stderr)
        )


def test_binary_rewriter_no_binary_error():
    rewriter = BinaryRewriter(binary=None)
    result = rewriter.rewrite_binary("out.bin", preserve_original=False)
    expect(not (result.success is not False))
