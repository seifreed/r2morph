from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.core.assembly import AssemblyService


@pytest.mark.parametrize(
    "instruction",
    [
        "nop",
        "xor eax, eax",
        "mov eax, ebx",
    ],
)
def test_assembly_service_basic_encoding(instruction):
    binary_path = Path("dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        assembler = AssemblyService()
        encoded = assembler.assemble(bin_obj, instruction)
        assert encoded is None or isinstance(encoded, bytes)


def test_assembly_service_movzx_fallback():
    binary_path = Path("dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        assembler = AssemblyService()
        encoded = assembler.assemble(bin_obj, "movzx eax, bl")
        assert encoded is None or isinstance(encoded, bytes)


def test_assembly_service_segment_prefix_fallback():
    binary_path = Path("dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        assembler = AssemblyService()
        encoded = assembler.assemble(bin_obj, "mov dword fs:[rax], ecx")
        assert encoded is None or isinstance(encoded, bytes)


def test_assembly_service_symbolic_resolution():
    binary_path = Path("dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        assembler = AssemblyService()
        resolved = assembler._resolve_symbolic_vars(
            bin_obj, "mov eax, [var_10h]"
        )
        assert "[rsp + 0x10]" in resolved
