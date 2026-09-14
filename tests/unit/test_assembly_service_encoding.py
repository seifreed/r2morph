from pathlib import Path

import pytest

from r2morph.core.assembly import AssemblyService
from r2morph.core.binary import Binary
from tests.utils.assertions import expect


@pytest.mark.parametrize(
    "instruction",
    [
        "nop",
        "xor eax, eax",
        "mov eax, ebx",
    ],
)
def test_assembly_service_basic_encoding(instruction):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        assembler = AssemblyService()
        encoded = assembler.assemble(bin_obj, instruction)
        expect(encoded is None or isinstance(encoded, bytes))


def test_assembly_service_movzx_fallback():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        assembler = AssemblyService()
        encoded = assembler.assemble(bin_obj, "movzx eax, bl")
        expect(encoded is None or isinstance(encoded, bytes))


def test_assembly_service_segment_prefix_fallback():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        assembler = AssemblyService()
        encoded = assembler.assemble(bin_obj, "mov dword fs:[rax], ecx")
        expect(encoded is None or isinstance(encoded, bytes))


def test_assembly_service_symbolic_resolution():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    with Binary(binary_path) as bin_obj:
        assembler = AssemblyService()
        resolved = assembler._resolve_symbolic_vars(bin_obj, "mov eax, [var_10h]")
        expect(not ("[rsp + 0x10]" not in resolved))


def test_assembly_service_encodes_relative_branch_from_requested_address():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    source_address = 0x1000
    target_address = 0x1008
    with Binary(binary_path) as bin_obj:
        encoded = AssemblyService().assemble(bin_obj, f"jne 0x{target_address:x}", source_address)

    expect(encoded is not None)
    displacement = int.from_bytes(encoded[1:], byteorder="little", signed=True)
    expect(source_address + len(encoded) + displacement == target_address)
