"""Native regression for no-base indexed FP operations in the engine VM."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass, _decode_run_item
from r2morph.mutations.code_virtualization_engine import VirtualizedFpArithMemOp, VirtualizedFpMemOp
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_fpengineidxnb_x86_64"
_EXPECTED_EXIT_CODE = 42

pytestmark = pytest.mark.integration


def test_engine_decodes_no_base_fp_indexed_load() -> None:
    item = _decode_run_item("movsd xmm0, qword ptr [rcx*8 + 0x402000]")

    expect(isinstance(item, VirtualizedFpMemOp) and item.kind == "fploadidxnb")


def test_engine_decodes_no_base_fp_indexed_arithmetic() -> None:
    item = _decode_run_item("addsd xmm0, qword ptr [rcx*8 + 0x402000]")

    expect(isinstance(item, VirtualizedFpArithMemOp) and item.base_index < 0)


def test_region_no_base_fp_indexed_fixture_virtualizes_complete_function(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated_fpidxnb"
    shutil.copyfile(_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260829}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(stats["partial_virtualization_total"] == 0 and stats["unsupported_functions_total"] == 0)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)


def test_engine_no_base_packed_indexed_moves_preserve_native_result(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("native ELF x86-64 execution requires Linux amd64")
    source = tmp_path / "packed_indexed.S"
    original = tmp_path / "packed_indexed"
    mutated = tmp_path / "packed_indexed_mutated"
    source.write_text(r"""
.text
.globl _start
.type _start, @function
_start:
    movq $1, %rcx
    movups values(,%rcx,8), %xmm0
    movups %xmm0, output(,%rcx,8)
    cpuid
    movl $60, %eax
    movl $1, %edi
    syscall
.size _start, .-_start
.section .rodata
.align 16
values:
    .long 10, 20, 30, 40
    .long 1, 2, 3, 4
.section .bss
.align 16
output:
    .zero 32
""")
    compile_result = run_command(["gcc", "-nostdlib", "-static", "-fno-pie", "-no-pie", source, "-o", original])
    expect(
        compile_result.returncode == 0,
        f"failed to compile the packed indexed engine fixture: {compile_result.stderr}",
    )
    original_result = run_command([original], timeout=30)
    shutil.copy2(original, mutated)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260830}).apply(binary)
        binary.save()
    finally:
        binary.close()

    mutated_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1 and original_result.returncode == mutated_result.returncode == 1,
        f"packed indexed memory virtualization changed the result: {stats=}, "
        f"original={original_result.returncode}, mutated={mutated_result.returncode}",
    )
