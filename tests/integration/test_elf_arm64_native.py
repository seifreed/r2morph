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

_COMPILED_SEQUENCE_SOURCE = """#include <stdint.h>
typedef int (*call_target)(int);
__attribute__((noinline)) static int direct_target(int value) {
    return value * 3 + 5;
}
__attribute__((noinline)) static int indirect_target(int value) {
    return (value ^ 21) - 2;
}
static call_target volatile selected_target = indirect_target;
__attribute__((noinline)) static int composed(int value) {
    uint32_t table[4] = {3, 5, 7, 11};
    int loaded = (int)table[value & 3];
    __asm__ volatile("mov x9, x9" ::: "x9");
    int result = selected_target(direct_target(value + loaded));
    for (int index = 0; index < 2; ++index) {
        result += index;
    }
    return (result ^ 42) & 127;
}
int main(void) {
    return composed(1);
}
"""
_AARCH64_LINUX_STARTUP_SOURCE = """.text
.global _start
.type _start,%function
.extern main
_start:
    bl main
    mov x8, #93
    svc #0
"""


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
        "    mov w1, #0x40\n"
        "    mov w1, w1\n"
        "    sub w1, w1, #22\n"
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
        "    mov w1, #0x40\n"
        "    mov w2, w1\n"
        "    mov w3, w3\n"
        "    cmp w2, #0\n"
        "    b.eq zero\n"
        "    sub w1, w1, #22\n"
        "    b done\n"
        "zero:\n"
        "    sub w1, w1, #22\n"
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


def _build_arm64_compiled_sequence(tmp_path: Path) -> Path:
    source = tmp_path / "arm64_compiled_sequence.c"
    source.write_text(_COMPILED_SEQUENCE_SOURCE, encoding="ascii")
    if platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}:
        compiler = shutil.which("aarch64-linux-gnu-gcc")
    else:
        compiler = shutil.which("cc") or shutil.which("clang")
    if compiler is None:
        raise RuntimeError("a native AArch64 C compiler is required for the compiled differential fixture")
    binary_path = tmp_path / "arm64_compiled_sequence"
    if platform.system() == "Linux":
        object_path = tmp_path / "arm64_compiled_sequence.o"
        startup_source = tmp_path / "arm64_startup.S"
        startup_object = tmp_path / "arm64_startup.o"
        startup_source.write_text(_AARCH64_LINUX_STARTUP_SOURCE, encoding="ascii")
        compile_flags = [
            "-O0",
            "-ffreestanding",
            "-fno-pie",
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-ffunction-sections",
            "-fdata-sections",
        ]
        run_command([compiler, *compile_flags, "-c", "-o", object_path, source], check=True, text=True)
        run_command([compiler, "-c", "-o", startup_object, startup_source], check=True, text=True)
        run_command(
            [
                compiler,
                "-nostdlib",
                "-static",
                "-Wl,-e,_start,--gc-sections",
                "-o",
                binary_path,
                startup_object,
                object_path,
            ],
            check=True,
            text=True,
        )
        return binary_path
    run_command(
        [
            compiler,
            "-O0",
            "-static",
            "-fno-pie",
            "-no-pie",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,--gc-sections",
            "-o",
            binary_path,
            source,
        ],
        check=True,
        text=True,
    )
    return binary_path


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


def test_elf_arm64_constant_unfolding_zero_preserves_native_exit_code(tmp_path: Path) -> None:
    _require_arm64_execution()

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
    compiler = shutil.which("aarch64-linux-gnu-gcc") if platform.system() == "Linux" else shutil.which("cc")
    if compiler is None:
        raise RuntimeError("an AArch64 assembler compiler is required for the constant fixture")
    binary_path = tmp_path / "arm64_constant"
    run_command(
        [compiler, "-nostdlib", "-static", "-Wl,-e,_start", "-x", "assembler", "-o", binary_path, source],
        check=True,
        text=True,
    )
    original = _run_arm64(binary_path)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = ConstantUnfoldingPass(config={"probability": 1.0, "seed": 20260919}).apply(binary)

    mutated = _run_arm64(binary_path)
    expect(
        result["mutations_applied"] > 0
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (42, "", ""),
        f"ARM64 constant unfolding changed native execution: {result=}",
    )


def test_elf_arm64_compiled_memory_and_call_sequence_preserves_native_exit_code(tmp_path: Path) -> None:
    _require_arm64_execution()

    binary_path = _build_arm64_compiled_sequence(tmp_path)
    original = _run_arm64(binary_path)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        results = (
            NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 20260921}).apply(binary),
            InstructionSubstitutionPass(
                config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": 20260921}
            ).apply(binary),
            RegisterSubstitutionPass(
                config={"max_substitutions_per_function": 2, "probability": 1.0, "seed": 20260921}
            ).apply(binary),
            ConstantUnfoldingPass(config={"probability": 1.0, "seed": 20260921}).apply(binary),
        )

    mutated = _run_arm64(binary_path)
    expect(
        all(result["mutations_applied"] > 0 for result in results)
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr),
        "compiled ELF ARM64 memory/call composition changed native execution: "
        f"original={original.returncode, original.stdout, original.stderr!r}; "
        f"mutated={mutated.returncode, mutated.stdout, mutated.stderr!r}; results={results!r}",
    )
