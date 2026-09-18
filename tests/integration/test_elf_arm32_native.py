"""Native differential coverage for the ELF ARM32 target."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from tests.utils.assertions import expect
from tests.utils.process import run_command


def _build_arm32_elf(tmp_path: Path) -> Path:
    compiler = shutil.which("arm-linux-gnueabihf-gcc")
    if compiler is None:
        raise RuntimeError("arm-linux-gnueabihf-gcc is required for the ELF ARM32 differential fixture")
    source = tmp_path / "arm32_exit.S"
    source.write_text(
        ".text\n"
        ".global _start\n"
        ".type _start,%function\n"
        "_start:\n"
        "    mov r1, #0\n"
        "    add r1, r1, #1\n"
        "    mov r0, #41\n"
        "    add r0, r0, #1\n"
        "    .rept 12\n"
        "    nop\n"
        "    .endr\n"
        "    mov r7, #1\n"
        "    svc #0\n"
        ".size _start, .-_start\n",
        encoding="ascii",
    )
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
