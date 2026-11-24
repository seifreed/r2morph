"""Verify referenced strings stay intact on native ARM64 Mach-O."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.engine import MorphEngine
from r2morph.mutations.string_obfuscation import StringObfuscationPass
from r2morph.platform.codesign import CodeSigner
from tests.utils.assertions import expect
from tests.utils.process import run_command


@pytest.mark.integration
def test_macho_arm64_string_obfuscation_preserves_native_observables(tmp_path: Path) -> None:
    if platform.system() != "Darwin" or platform.machine().lower() not in {"arm64", "aarch64"}:
        pytest.skip("native ARM64 Mach-O execution requires an Apple Silicon macOS host")
    clang = shutil.which("clang")
    if clang is None:
        raise FileNotFoundError("clang is required for the native ARM64 Mach-O integration test")

    source = tmp_path / "macho_arm64_string.c"
    source.write_text(
        "#include <stdio.h>\n"
        '__attribute__((used)) static const char evidence[] = "macho-arm64-string-evidence";\n'
        "__attribute__((noinline)) int transform(int value) { return value + 1; }\n"
        'int main(void) { puts("hello"); return transform(41) == 42 ? 0 : 1; }\n',
        encoding="ascii",
    )
    original = tmp_path / "macho_arm64_string"
    run_command(
        [clang, "-arch", "arm64", "-O0", "-fno-inline", "-o", original, source],
        check=True,
        text=True,
        timeout=30,
    )
    protected = tmp_path / "macho_arm64_string_obfuscated"
    original_result = run_command([original], capture_output=True, text=True, timeout=30)

    with MorphEngine(config={"seed": 1337}) as engine:
        engine.load_binary(original).analyze("aa")
        engine.add_mutation(
            StringObfuscationPass({"probability": 1.0, "encoding": "xor", "max_strings_per_section": 1})
        )
        result = engine.run()
        engine.save(protected)

    obfuscated_result = run_command([protected], capture_output=True, text=True, timeout=30)
    pass_result = result["pass_results"]["StringObfuscation"]
    expect(
        pass_result["mutations_applied"] == 1
        and b"macho-arm64-string-evidence" not in protected.read_bytes()
        and b"hello" in protected.read_bytes()
        and b"macho-arm64-string-evidence" in original.read_bytes()
        and CodeSigner().verify(protected)
        and (original_result.returncode, original_result.stdout, original_result.stderr)
        == (obfuscated_result.returncode, obfuscated_result.stdout, obfuscated_result.stderr)
        == (0, "hello\n", "")
    )
