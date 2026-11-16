"""Verify native x86-64 Mach-O mutation under macOS execution."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core import randomness
from r2morph.core.binary import Binary
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.platform.codesign import CodeSigner
from tests.utils.assertions import expect
from tests.utils.process import run_command


def _build_x86_64_macho(tmp_path: Path) -> Path:
    clang = shutil.which("clang")
    if clang is None:
        raise FileNotFoundError("clang is required for the native Mach-O integration test")
    source = tmp_path / "macho_x86_64.c"
    source.write_text(
        "#include <stdio.h>\n"
        "__attribute__((noinline)) long transform(long value) {\n"
        '    __asm__ volatile("mov %0, %%r8\\n\\tadd $1, %%r8\\n\\tmov %%r8, %0" '
        ': "+r"(value) : : "r8", "cc");\n'
        "    return value;\n"
        "}\n"
        'int main(void) { puts("hello"); return transform(41) == 42 ? 0 : 1; }\n',
        encoding="utf-8",
    )
    binary = tmp_path / "macho_x86_64"
    run_command(
        [clang, "-arch", "x86_64", "-O0", "-fno-inline", "-o", binary, source],
        check=True,
        text=True,
        timeout=30,
    )
    return binary


def _execute_x86_64_macho(binary: Path) -> tuple[int, str, str]:
    arch = shutil.which("arch")
    if arch is None:
        raise FileNotFoundError("arch is required for x86-64 Mach-O execution")
    result = run_command(
        [arch, "-x86_64", binary],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    return result.returncode, result.stdout, result.stderr


@pytest.mark.integration
def test_macho_x86_64_instruction_substitution_preserves_native_observables(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("x86-64 Mach-O execution requires macOS")

    original = _build_x86_64_macho(tmp_path)
    protected = tmp_path / "macho_x86_64_substituted"
    shutil.copy2(original, protected)
    with Binary(protected, writable=True) as binary:
        binary.analyze("aa")
        result = InstructionSubstitutionPass({"probability": 1.0, "force_different": True}).apply(binary)
        binary.save()

    expect(
        result["mutations_applied"] > 0
        and _execute_x86_64_macho(original) == _execute_x86_64_macho(protected) == (0, "hello\n", "")
    )


@pytest.mark.integration
def test_macho_x86_64_register_substitution_preserves_native_observables(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("x86-64 Mach-O execution requires macOS")

    original = _build_x86_64_macho(tmp_path)
    protected = tmp_path / "macho_x86_64_register_substituted"
    shutil.copy2(original, protected)
    randomness.seed(1)
    with Binary(protected, writable=True) as binary:
        binary.analyze("aa")
        result = RegisterSubstitutionPass({"probability": 1.0, "max_substitutions_per_function": 3}).apply(binary)
        binary.save()

    signed = CodeSigner().sign(protected, adhoc=True)
    expect(
        signed
        and result["mutations_applied"] > 0
        and _execute_x86_64_macho(original) == _execute_x86_64_macho(protected) == (0, "hello\n", "")
    )
