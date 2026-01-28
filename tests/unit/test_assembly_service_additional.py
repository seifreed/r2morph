from pathlib import Path

import pytest

from r2morph.core.assembly import AssemblyService
from r2morph.core.binary import Binary


def test_assembly_service_fallbacks():
    asm_service = AssemblyService()

    assert asm_service._assemble_movzx_movsx_fallback("movzx eax, bl") is not None
    assert asm_service._assemble_movzx_movsx_fallback("movsx eax, bl") is not None
    assert asm_service._assemble_movzx_movsx_fallback("movzx foo, bar") is None


def test_assembly_service_resolve_symbolic_vars():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        asm_service = AssemblyService()
        resolved = asm_service._resolve_symbolic_vars(bin_obj, "mov eax, [arg_10h]")

    assert "rsp" in resolved.lower()
