import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.utils.assertions import expect
from tests.utils.process import run_command


def _build_arm64_elf(tmp_path: Path, complex_fixture: bool = False) -> Path:
    if platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}:
        compiler = shutil.which("aarch64-linux-gnu-gcc")
    else:
        compiler = shutil.which("cc") or shutil.which("clang")
    if compiler is None:
        raise RuntimeError("an AArch64 assembler compiler is required for the ELF AArch64 differential fixture")
    source = tmp_path / "arm64_exit.S"
    basic_source = (
        ".text\n"
        ".global _start\n"
        ".type _start,%function\n"
        "_start:\n"
        "    bl compute\n"
        "    mov w8, #93\n"
        "    svc #0\n"
        ".type compute,%function\n"
        "compute:\n"
        "    mov w1, #37\n"
        "    mov w1, w1\n"
        "    add w1, w1, #5\n"
        "    mov w0, w1\n"
        "    ret\n"
        ".size _start, .-_start\n"
    )
    complex_source = (
        ".text\n"
        ".global _start\n"
        ".type _start,%function\n"
        "_start:\n"
        "    bl compute\n"
        "    mov w8, #93\n"
        "    svc #0\n"
        ".type compute,%function\n"
        "compute:\n"
        "    mov w1, #37\n"
        "    mov w2, w1\n"
        "    mov w3, w3\n"
        "    cmp w2, #0\n"
        "    b.eq zero\n"
        "    add w1, w1, #5\n"
        "    b done\n"
        "zero:\n"
        "    add w1, w1, #5\n"
        "done:\n"
        "    mov w0, w1\n"
        "    ret\n"
        ".size _start, .-_start\n"
    )
    source.write_text(complex_source if complex_fixture else basic_source, encoding="ascii")
    binary_path = tmp_path / "arm64_elf"
    command = [
        compiler,
        "-nostdlib",
        "-static",
        "-Wl,-e,_start",
        "-x",
        "assembler",
        "-o",
        str(binary_path),
        str(source),
    ]
    run_command(command, check=True, text=True)
    return binary_path


def _run_arm64(binary_path: Path):
    if platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}:
        emulator = shutil.which("qemu-aarch64")
        if emulator is None:
            raise RuntimeError("qemu-aarch64 is required for the ELF AArch64 differential fixture")
        return run_command([emulator, binary_path], text=True, timeout=30)
    return run_command([binary_path], text=True, timeout=30)


def _require_arm64_execution() -> None:
    if platform.system() == "Linux" and (
        platform.machine().lower() in {"aarch64", "arm64"}
        or (
            platform.machine().lower() in {"x86_64", "amd64"}
            and shutil.which("aarch64-linux-gnu-gcc")
            and shutil.which("qemu-aarch64")
        )
    ):
        return
    pytest.skip("ELF AArch64 differential execution requires Linux AArch64 or Linux qemu-aarch64")


def test_elf_arm64_nop_insertion_preserves_native_exit_code(tmp_path: Path) -> None:
    _require_arm64_execution()

    binary_path = _build_arm64_elf(tmp_path)
    original = _run_arm64(binary_path)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 1337}).apply(binary)

    mutated = _run_arm64(binary_path)
    expect(
        result["mutations_applied"] > 0
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "native ELF ARM64 NOP insertion changed execution",
    )


def test_elf_arm64_instruction_substitution_preserves_native_exit_code(tmp_path: Path) -> None:
    _require_arm64_execution()

    binary_path = _build_arm64_elf(tmp_path)
    original = _run_arm64(binary_path)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = InstructionSubstitutionPass(
            config={"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        ).apply(binary)

    mutated = _run_arm64(binary_path)
    expect(
        result["mutations_applied"] > 0
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "native ELF ARM64 instruction substitution changed execution",
    )


def test_elf_arm64_register_substitution_preserves_native_exit_code(tmp_path: Path) -> None:
    _require_arm64_execution()

    binary_path = _build_arm64_elf(tmp_path)
    original = _run_arm64(binary_path)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        pass_instance = RegisterSubstitutionPass(
            config={"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        )
        result = pass_instance.apply(binary)

    mutated = _run_arm64(binary_path)
    expect(
        result["mutations_applied"] > 0
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "native ELF ARM64 register substitution changed execution: "
        f"original={original.returncode, original.stdout, original.stderr!r}; "
        f"mutated={mutated.returncode, mutated.stdout, mutated.stderr!r}; "
        f"result={result!r}; "
        f"mutations={[record.mutated_disasm for record in pass_instance.get_records()]!r}",
    )


def test_elf_arm64_complex_pass_sequence_preserves_native_exit_code(tmp_path: Path) -> None:
    _require_arm64_execution()

    binary_path = _build_arm64_elf(tmp_path, complex_fixture=True)
    original = _run_arm64(binary_path)

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

    mutated = _run_arm64(binary_path)
    expect(
        all(result["mutations_applied"] > 0 for result in results)
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        "complex ELF ARM64 mutation sequence changed native execution: "
        f"original={original.returncode, original.stdout, original.stderr!r}; "
        f"mutated={mutated.returncode, mutated.stdout, mutated.stderr!r}; "
        f"results={results!r}",
    )
