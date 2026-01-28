from pathlib import Path
import shutil

import pytest

from r2morph.core.binary import Binary


def test_binary_write_instruction_and_nop_fill(tmp_path: Path):
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "binary_core_ops"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        functions = bin_obj.get_functions()
        if not functions:
            pytest.skip("No functions found")

        addr = functions[0].get("offset", functions[0].get("addr", 0))
        assert addr

        assert bin_obj.write_instruction(addr, "nop") is True
        assert bin_obj.nop_fill(addr, 3) is True

        saved_path = tmp_path / "binary_saved"
        bin_obj.save(saved_path)
        assert saved_path.exists()


def test_binary_resolve_symbolic_vars_fallback():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        resolved = bin_obj._resolve_symbolic_vars("mov eax, [var_10h]")

    assert "rsp" in resolved.lower()


def test_binary_movzx_fallback_encoding():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        encoded = bin_obj._assemble_movzx_movsx_fallback("movzx eax, bl")

    assert encoded is not None
    assert isinstance(encoded, (bytes, bytearray))
