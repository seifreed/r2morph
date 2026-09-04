from pathlib import Path

import pytest

from r2morph.core.assembly import AssemblyService
from r2morph.core.binary import Binary
from tests.utils.assertions import expect


def test_assembly_service_fallbacks():
    asm_service = AssemblyService()

    expect(asm_service._assemble_movzx_movsx_fallback("movzx eax, bl") is not None)
    expect(asm_service._assemble_movzx_movsx_fallback("movsx eax, bl") is not None)
    expect(not (asm_service._assemble_movzx_movsx_fallback("movzx foo, bar") is not None))


def test_movd_fallback_encodes_xmm_to_gp_register() -> None:
    expect(AssemblyService._assemble_movd_fallback("movd edx, xmm6") == b"\x66\x0f\x7e\xf2")


def test_assembly_service_resolve_symbolic_vars():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        asm_service = AssemblyService()
        resolved = asm_service._resolve_symbolic_vars(bin_obj, "mov eax, [arg_10h]")

    expect(not ("rsp" not in resolved.lower()))
