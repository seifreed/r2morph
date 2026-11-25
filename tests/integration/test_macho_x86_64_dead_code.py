"""Native Intel Mach-O regression for dead-code injection."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.platform.codesign import CodeSigner
from tests.utils.assertions import expect
from tests.utils.process import run_command


def _build_macho_with_nop_padding(tmp_path: Path) -> Path:
    clang = shutil.which("clang")
    if clang is None:
        raise FileNotFoundError("clang is required for the native Mach-O integration test")
    source = tmp_path / "macho_x86_64_padding.c"
    nop_sled = r"nop\n\t" * 31 + "nop"
    source.write_text(
        "#include <stdio.h>\n"
        "__attribute__((noinline)) long transform(long value) {\n"
        f'    __asm__ volatile("{nop_sled}" ::: "rax", "cc");\n'
        "    return value + 1;\n"
        "}\n"
        'int main(void) { puts("hello"); return transform(41) == 42 ? 0 : 1; }\n',
        encoding="utf-8",
    )
    binary = tmp_path / "macho_x86_64_padding"
    run_command(
        [clang, "-arch", "x86_64", "-O0", "-fno-inline", "-o", binary, source],
        check=True,
        text=True,
        timeout=30,
    )
    return binary


def _execute_macho(binary: Path) -> tuple[int, str, str]:
    result = run_command([binary], capture_output=True, check=False, text=True, timeout=30)
    return result.returncode, result.stdout, result.stderr


@pytest.mark.integration
def test_macho_x86_64_dead_code_injection_preserves_native_observables(tmp_path: Path) -> None:
    if platform.system() != "Darwin":
        pytest.skip("x86-64 Mach-O execution requires macOS")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("native x86-64 Mach-O execution requires an Intel macOS host")

    original = _build_macho_with_nop_padding(tmp_path)
    protected = tmp_path / "macho_x86_64_dead_code_injected"
    shutil.copy2(original, protected)
    with Binary(protected, writable=True) as binary:
        binary.analyze("aa")
        result = DeadCodeInjectionPass(
            {
                "probability": 1.0,
                "max_injections_per_function": 1,
                "min_padding_size": 16,
                "code_complexity": "medium",
                "seed": 1338,
            }
        ).apply(binary)
        binary.save()

    bytes_changed = protected.read_bytes() != original.read_bytes()
    signed = CodeSigner().sign(protected, adhoc=True)
    verified = CodeSigner().verify(protected)
    original_result = _execute_macho(original)
    injected_result = _execute_macho(protected)
    expect(
        result["mutations_applied"] > 0
        and bytes_changed
        and signed
        and verified
        and original_result == injected_result == (0, "hello\n", ""),
        f"mutation={result}, bytes_changed={bytes_changed}, signed={signed}, "
        f"verified={verified}, original={original_result}, injected={injected_result}",
    )
