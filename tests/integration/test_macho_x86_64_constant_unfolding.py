"""Differential native smoke for x86-64 Mach-O constant unfolding."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.constant_unfolding import ConstantUnfoldingPass
from tests.utils.assertions import expect
from tests.utils.process import run_command


@pytest.mark.integration
def test_macho_x86_64_constant_unfolding_preserves_native_observables(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("x86-64 Mach-O execution requires macOS")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native x86-64 Mach-O execution requires an Intel macOS host")

    clang = shutil.which("clang")
    if clang is None:
        raise FileNotFoundError("clang is required for the native Mach-O integration test")
    source = tmp_path / "macho_x86_64_constant.c"
    source.write_text(
        "#include <stdio.h>\n"
        "__attribute__((noinline)) static long transform(long value) {\n"
        '    __asm__ volatile("addq $3, %0" : "+r"(value) : : "cc");\n'
        "    return value;\n"
        "}\n"
        'int main(void) { puts("hello"); return transform(39) == 42 ? 0 : 1; }\n',
        encoding="utf-8",
    )
    original = tmp_path / "macho_x86_64_constant"
    run_command(
        [clang, "-arch", "x86_64", "-O0", "-fno-inline", "-o", original, source],
        check=True,
        text=True,
        timeout=30,
    )
    protected = tmp_path / "macho_x86_64_constant_unfolded"
    shutil.copy2(original, protected)
    before = run_command([original], capture_output=True, check=False, text=True, timeout=30)

    with Binary(protected, writable=True) as binary:
        binary.analyze("aa")
        result = ConstantUnfoldingPass({"probability": 1.0, "seed": 20261126}).apply(binary)

    after = run_command([protected], capture_output=True, check=False, text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (before.returncode, before.stdout, before.stderr)
        == (after.returncode, after.stdout, after.stderr)
        == (0, "hello\n", ""),
        f"Mach-O constant unfolding changed native observables: {result=}",
    )
