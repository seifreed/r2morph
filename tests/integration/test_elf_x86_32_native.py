"""Native differential coverage for the ELF x86 32-bit target."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.utils.assertions import expect
from tests.utils.process import run_command


def _build_x86_32_elf(tmp_path: Path, complex_fixture: bool = False) -> Path:
    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("clang or gcc is required for the ELF x86 32-bit differential fixture")
    target_flags = ["-target", "i386-linux-gnu"] if Path(compiler).name == "clang" else ["-m32"]
    source = tmp_path / "x86_32_exit.S"
    basic_source = (
        ".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "    call compute\n"
        "    movl %eax, %ebx\n"
        "    movl $0, %ecx\n"
        "    movl $1, %eax\n"
        "    int $0x80\n"
        ".type compute,@function\n"
        "compute:\n"
        "    movl $40, %ecx\n"
        "    movl %ecx, %ecx\n"
        "    addl $2, %ecx\n"
        "    movl %ecx, %eax\n"
        "    ret\n"
        ".size _start, .-_start\n"
    )
    complex_source = (
        ".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "    call compute\n"
        "    movl %eax, %ebx\n"
        "    movl $0, %ecx\n"
        "    movl $1, %eax\n"
        "    int $0x80\n"
        ".type compute,@function\n"
        "compute:\n"
        "    movl $40, %ecx\n"
        "    movl %ecx, %ecx\n"
        "    movl $2, %esi\n"
        "    cmpl $0, %ecx\n"
        "    je zero\n"
        "    addl %esi, %ecx\n"
        "    jmp done\n"
        "zero:\n"
        "    addl %esi, %ecx\n"
        "done:\n"
        "    movl %ecx, %eax\n"
        "    ret\n"
        ".size _start, .-_start\n"
    )
    source.write_text(complex_source if complex_fixture else basic_source, encoding="ascii")
    binary_path = tmp_path / "x86_32_exit"
    run_command(
        [
            compiler,
            *target_flags,
            "-nostdlib",
            "-static",
            "-Wl,-e,_start",
            "-x",
            "assembler",
            "-o",
            binary_path,
            source,
        ],
        check=True,
        text=True,
    )
    return binary_path


def _build_x86_32_expansion_elf(tmp_path: Path) -> Path:
    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("clang or gcc is required for the ELF x86 32-bit expansion fixture")
    target_flags = ["-target", "i386-linux-gnu"] if Path(compiler).name == "clang" else ["-m32"]
    source = tmp_path / "x86_32_expansion.S"
    source.write_text(
        ".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "    call compute\n"
        "    movl %eax, %ebx\n"
        "    movl $1, %eax\n"
        "    int $0x80\n"
        ".type compute,@function\n"
        "compute:\n"
        "    movl $20, %ecx\n"
        "    movl %ecx, %edx\n"
        "    xorl %edx, %edx\n"
        "    movl %ecx, %edx\n"
        "    shll $1, %ecx\n"
        "    addl $2, %ecx\n"
        "    movl %ecx, %eax\n"
        "    nop\n"
        "    ret\n"
        ".size compute, .-compute\n",
        encoding="ascii",
    )
    binary_path = tmp_path / "x86_32_expansion"
    run_command(
        [
            compiler,
            *target_flags,
            "-nostdlib",
            "-static",
            "-Wl,-e,_start",
            "-x",
            "assembler",
            "-o",
            binary_path,
            source,
        ],
        check=True,
        text=True,
    )
    return binary_path


def test_elf_x86_32_instruction_substitution_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_elf(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        mutation_pass = InstructionSubstitutionPass(
            config={"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        )
        result = mutation_pass.apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF x86 32-bit instruction substitution changed native execution",
    )


def test_elf_x86_32_nop_insertion_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_elf(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 1337}).apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF x86 32-bit NOP insertion changed native execution",
    )


def test_elf_x86_32_register_substitution_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_elf(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = RegisterSubstitutionPass(
            config={"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        ).apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF x86 32-bit register substitution changed native execution",
    )


def test_elf_x86_32_complex_pass_sequence_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_elf(tmp_path, complex_fixture=True)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        results = (
            RegisterSubstitutionPass(
                config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": 20260919}
            ).apply(binary),
            NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 20260919}).apply(binary),
            InstructionSubstitutionPass(
                config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": 20260919}
            ).apply(binary),
        )

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(
        all(result["mutations_applied"] > 0 for result in results)
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "complex ELF x86 32-bit mutation sequence changed native execution: "
        f"original={original.returncode, original.stdout, original.stderr!r}; "
        f"mutated={mutated.returncode, mutated.stdout, mutated.stderr!r}; "
        f"results={results!r}",
    )


def test_elf_x86_32_constant_unfolding_zero_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("clang or gcc is required for the ELF x86 32-bit differential fixture")
    target_flags = ["-target", "i386-linux-gnu"] if Path(compiler).name == "clang" else ["-m32"]
    source = tmp_path / "x86_32_constant.S"
    binary_path = tmp_path / "x86_32_constant"
    source.write_text(
        ".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "    call compute\n"
        "    movl %eax, %ebx\n"
        "    movl $1, %eax\n"
        "    int $0x80\n"
        ".type compute,@function\n"
        "compute:\n"
        "    movl $0, %ecx\n"
        "    addl $42, %ecx\n"
        "    movl %ecx, %eax\n"
        "    ret\n"
        ".size _start, .-_start\n",
        encoding="ascii",
    )
    run_command(
        [
            compiler,
            *target_flags,
            "-nostdlib",
            "-static",
            "-Wl,-e,_start",
            "-x",
            "assembler",
            "-o",
            binary_path,
            source,
        ],
        check=True,
        text=True,
    )
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = ConstantUnfoldingPass(config={"probability": 1.0, "seed": 20260919}).apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        f"x86 32-bit constant unfolding changed native execution: {result=}",
    )


def test_elf_x86_32_instruction_expansion_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")

    binary_path = _build_x86_32_expansion_elf(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = InstructionExpansionPass(
            config={"max_expansions_per_function": 1, "probability": 1.0, "seed": 20260923}
        ).apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF x86 32-bit instruction expansion changed native execution",
    )
