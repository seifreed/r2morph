import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.nop_insertion import NopInsertionPass
from tests.utils.assertions import expect
from tests.utils.process import run_command


def _build_arm64_elf(tmp_path: Path) -> Path:
    compiler = shutil.which("cc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")
    source = tmp_path / "arm64_elf.c"
    source.write_text(
        "__attribute__((noinline)) int transform(int value) {\n"
        "    volatile int cell = value;\n"
        '    __asm__ volatile("mov w8, w8" ::: "w8");\n'
        "    return cell + 5;\n"
        "}\n"
        "int main(void) { return transform(37) == 42 ? 0 : 1; }\n"
    )
    binary_path = tmp_path / "arm64_elf"
    run_command(
        [compiler, "-O0", "-fno-inline", "-o", str(binary_path), str(source)],
        check=True,
        text=True,
    )
    return binary_path


def test_elf_arm64_nop_insertion_preserves_native_exit_code(tmp_path: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"aarch64", "arm64"}:
        pytest.skip("native ELF ARM64 execution requires a Linux ARM64 runner")

    binary_path = _build_arm64_elf(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as binary:
        binary.analyze()
        result = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 1337}).apply(binary)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (original.returncode, original.stdout, original.stderr)
        == (mutated.returncode, mutated.stdout, mutated.stderr)
        == (0, "", ""),
        "native ELF ARM64 NOP insertion changed execution",
    )
