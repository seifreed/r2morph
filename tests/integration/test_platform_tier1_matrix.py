"""Differential matrix for Tier 1 passes on preview ELF architectures."""

from __future__ import annotations

import platform
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass
from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.integration.test_elf_arm32_native import _build_arm32_elf
from tests.integration.test_elf_arm64_native import _build_arm64_elf, _require_arm64_execution, _run_arm64
from tests.integration.test_elf_x86_32_native import _build_x86_32_elf
from tests.utils.assertions import expect
from tests.utils.process import run_command

_EXPECTED_EXIT_CODE = 42
_PassFactory = Callable[[int], MutationPass]
_TIER1_PASS_NAMES = (
    "InstructionSubstitution",
    "NopInsertion",
    "RegisterSubstitution",
    "ConstantUnfolding",
)


def _build_pass(mutation_name: str, seed: int) -> MutationPass:
    if mutation_name == "InstructionSubstitution":
        return InstructionSubstitutionPass(
            config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": seed}
        )
    if mutation_name == "NopInsertion":
        return NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": seed})
    if mutation_name == "RegisterSubstitution":
        return RegisterSubstitutionPass(config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": seed})
    if mutation_name == "ConstantUnfolding":
        return ConstantUnfoldingPass(config={"probability": 1.0, "seed": seed})
    raise ValueError(f"unknown Tier 1 pass: {mutation_name}")


def _require_arm32_execution() -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("ELF ARM32 differential execution requires a Linux x86-64 runner with qemu-arm")
    if shutil.which("arm-linux-gnueabihf-gcc") is None or shutil.which("qemu-arm") is None:
        pytest.skip("ELF ARM32 differential execution requires the cross compiler and qemu-arm")


def _require_x86_32_execution() -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native ELF x86 32-bit execution requires a Linux x86-64 runner")
    if shutil.which("clang") is None:
        pytest.skip("ELF x86 32-bit differential execution requires clang")


def _build_target(target: str, tmp_path: Path, mutation_name: str) -> tuple[Path, Callable[[Path], object]]:
    if target == "arm32":
        _require_arm32_execution()
        if mutation_name == "ConstantUnfolding":
            source = tmp_path / "arm32_constant.S"
            source.write_text(
                ".text\n.global _start\n_start:\n"
                "bl compute\nmov r7, #1\nsvc #0\n"
                "compute:\nmov r2, #0\nadd r2, r2, #42\nmov r0, r2\nbx lr\n",
                encoding="ascii",
            )
            binary_path = tmp_path / "arm32_constant"
            run_command(
                [
                    "arm-linux-gnueabihf-gcc",
                    "-marm",
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
        else:
            binary_path = _build_arm32_elf(tmp_path)
        return binary_path, lambda path: run_command(["qemu-arm", path], text=True, timeout=30)
    if target == "arm64":
        _require_arm64_execution()
        if mutation_name == "ConstantUnfolding":
            source = tmp_path / "arm64_constant.S"
            source.write_text(
                ".text\n"
                ".global _start\n"
                ".type _start,%function\n"
                "_start:\n"
                "    bl compute\n"
                "    mov w8, #93\n"
                "    svc #0\n"
                ".type compute,%function\n"
                "compute:\n"
                "    mov w1, #0\n"
                "    add w1, w1, #42\n"
                "    mov w0, w1\n"
                "    ret\n"
                ".size _start, .-_start\n",
                encoding="ascii",
            )
            binary_path = tmp_path / "arm64_constant"
            compiler = shutil.which("aarch64-linux-gnu-gcc") or shutil.which("cc")
            if compiler is None:
                raise RuntimeError("an AArch64 assembler compiler is required for the constant fixture")
            run_command(
                [compiler, "-nostdlib", "-static", "-Wl,-e,_start", "-x", "assembler", "-o", binary_path, source],
                check=True,
                text=True,
            )
            return binary_path, _run_arm64
        return _build_arm64_elf(tmp_path), _run_arm64
    if target == "x86-32":
        _require_x86_32_execution()
        return _build_x86_32_elf(tmp_path), lambda path: run_command([path], text=True, timeout=30)
    raise ValueError(f"unknown preview target: {target}")


@pytest.mark.parametrize("target", ("arm32", "arm64", "x86-32"))
@pytest.mark.parametrize("mutation_name", _TIER1_PASS_NAMES)
def test_tier1_pass_preview_target_preserves_exit_code(
    target: str,
    mutation_name: str,
    tmp_path: Path,
) -> None:
    binary_path, execute = _build_target(target, tmp_path, mutation_name)
    original = execute(binary_path)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        seed = 20260919 if mutation_name == "ConstantUnfolding" else 1337
        result = _build_pass(mutation_name, seed).apply(binary)

    mutated = execute(binary_path)
    expect(
        result.get("mutations_applied", 0) > 0
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (_EXPECTED_EXIT_CODE, "", ""),
        f"{mutation_name} changed {target} execution: {result=}",
    )
