"""Native differential coverage for the ELF ARM32 target."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.utils.assertions import expect
from tests.utils.process import run_command


def _build_arm32_elf(tmp_path: Path, complex_fixture: bool = False) -> Path:
    compiler = shutil.which("arm-linux-gnueabihf-gcc")
    if compiler is None:
        raise RuntimeError("arm-linux-gnueabihf-gcc is required for the ELF ARM32 differential fixture")
    source = tmp_path / "arm32_exit.S"
    basic_source = (
        ".text\n"
        ".global _start\n"
        ".type _start,%function\n"
        "_start:\n"
        "    bl compute\n"
        "    mov r7, #1\n"
        "    svc #0\n"
        ".type compute,%function\n"
        "compute:\n"
        "    mov r2, #40\n"
        "    mov r2, r2\n"
        "    add r2, r2, #2\n"
        "    mov r0, r2\n"
        "    bx lr\n"
        ".size _start, .-_start\n"
    )
    complex_source = (
        ".text\n"
        ".global _start\n"
        ".type _start,%function\n"
        "_start:\n"
        "    bl compute\n"
        "    mov r7, #1\n"
        "    svc #0\n"
        ".type compute,%function\n"
        "compute:\n"
        "    mov r2, #40\n"
        "    mov r3, r2\n"
        "    mov r4, r4\n"
        "    cmp r3, #0\n"
        "    beq zero\n"
        "    add r2, r2, #2\n"
        "    b done\n"
        "zero:\n"
        "    add r2, r2, #2\n"
        "done:\n"
        "    mov r0, r2\n"
        "    bx lr\n"
        ".size _start, .-_start\n"
    )
    source.write_text(complex_source if complex_fixture else basic_source, encoding="ascii")
    binary_path = tmp_path / "arm32_exit"
    run_command(
        [
            compiler,
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


def test_elf_arm32_instruction_substitution_preserves_emulated_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("ELF ARM32 differential execution requires a Linux x86-64 runner with qemu-arm")
    if shutil.which("qemu-arm") is None:
        raise RuntimeError("qemu-arm is required for the ELF ARM32 differential fixture")

    binary_path = _build_arm32_elf(tmp_path)
    original = run_command(["qemu-arm", binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        mutation_pass = InstructionSubstitutionPass(
            config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": 1337}
        )
        result = mutation_pass.apply(binary)

    mutated = run_command(["qemu-arm", binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF ARM32 instruction substitution changed emulated execution",
    )


def test_elf_arm32_nop_insertion_preserves_emulated_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("ELF ARM32 differential execution requires a Linux x86-64 runner with qemu-arm")
    if shutil.which("qemu-arm") is None:
        raise RuntimeError("qemu-arm is required for the ELF ARM32 differential fixture")

    binary_path = _build_arm32_elf(tmp_path)
    original = run_command(["qemu-arm", binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 1337}).apply(binary)

    mutated = run_command(["qemu-arm", binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF ARM32 NOP insertion changed emulated execution",
    )


def test_elf_arm32_register_substitution_preserves_emulated_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("ELF ARM32 differential execution requires a Linux x86-64 runner with qemu-arm")
    if shutil.which("qemu-arm") is None:
        raise RuntimeError("qemu-arm is required for the ELF ARM32 differential fixture")

    binary_path = _build_arm32_elf(tmp_path)
    original = run_command(["qemu-arm", binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = RegisterSubstitutionPass(
            config={"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        ).apply(binary)

    mutated = run_command(["qemu-arm", binary_path], text=True, timeout=30)
    expect(result["mutations_applied"] > 0)
    expect(
        (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "ELF ARM32 register substitution changed emulated execution",
    )


def test_elf_arm32_complex_pass_sequence_preserves_emulated_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("ELF ARM32 differential execution requires a Linux x86-64 runner with qemu-arm")
    if shutil.which("qemu-arm") is None:
        raise RuntimeError("qemu-arm is required for the ELF ARM32 differential fixture")

    binary_path = _build_arm32_elf(tmp_path, complex_fixture=True)
    original = run_command(["qemu-arm", binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        results = (
            NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 20260919}).apply(binary),
            InstructionSubstitutionPass(
                config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": 20260919}
            ).apply(binary),
            RegisterSubstitutionPass(
                config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": 20260919}
            ).apply(binary),
        )

    mutated = run_command(["qemu-arm", binary_path], text=True, timeout=30)
    expect(
        all(result["mutations_applied"] > 0 for result in results)
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "complex ELF ARM32 mutation sequence changed emulated execution: "
        f"original={original.returncode, original.stdout, original.stderr!r}; "
        f"mutated={mutated.returncode, mutated.stdout, mutated.stderr!r}; "
        f"results={results!r}",
    )


def test_elf_arm32_constant_unfolding_zero_preserves_emulated_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("ELF ARM32 differential execution requires a Linux x86-64 runner with qemu-arm")
    if shutil.which("qemu-arm") is None:
        raise RuntimeError("qemu-arm is required for the ELF ARM32 differential fixture")

    compiler = shutil.which("arm-linux-gnueabihf-gcc")
    if compiler is None:
        raise RuntimeError("arm-linux-gnueabihf-gcc is required for the ELF ARM32 differential fixture")
    source = tmp_path / "arm32_constant.S"
    source.write_text(
        ".text\n"
        ".global _start\n"
        ".type _start,%function\n"
        "_start:\n"
        "    bl compute\n"
        "    mov r7, #1\n"
        "    svc #0\n"
        ".type compute,%function\n"
        "compute:\n"
        "    mov r2, #0\n"
        "    add r2, r2, #42\n"
        "    mov r0, r2\n"
        "    bx lr\n"
        ".size _start, .-_start\n",
        encoding="ascii",
    )
    binary_path = tmp_path / "arm32_constant"
    run_command(
        [compiler, "-marm", "-nostdlib", "-static", "-Wl,-e,_start", "-x", "assembler", "-o", binary_path, source],
        check=True,
        text=True,
    )
    original = run_command(["qemu-arm", binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = ConstantUnfoldingPass(config={"probability": 1.0, "seed": 20260919}).apply(binary)

    mutated = run_command(["qemu-arm", binary_path], text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        f"ARM32 constant unfolding changed emulated execution: {result=}",
    )
