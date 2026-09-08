import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.platform.codesign import CodeSigner
from tests.utils.assertions import expect
from tests.utils.process import run_command


def test_register_substitution_arm64_real_binary_skips_implicit_link_register(tmp_path: Path):
    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "arm64_reg_sub"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = RegisterSubstitutionPass(config={"probability": 1.0, "seed": 1337})
        result = pass_obj.apply(bin_obj)

    expect(result.get("mutations_applied", 0) == 0)


def test_register_substitution_arm64_preserves_generated_native_execution(tmp_path: Path):
    if shutil.which("clang") is None:
        pytest.skip("clang not available")

    source = tmp_path / "arm64_register_substitution.c"
    source.write_text(
        "__attribute__((naked, noinline)) int transform(int value) {\n"
        '    __asm__("add w8, w0, #2\\n"\n'
        '            "mov w0, w8\\n"\n'
        '            "ret\\n");\n'
        "}\n"
        "int main(void) { return transform(40) == 42 ? 0 : 1; }\n"
    )
    binary_path = tmp_path / "arm64_register_substitution"
    run_command(
        [
            "clang",
            "-arch",
            "arm64",
            "-O0",
            "-fno-inline",
            "-o",
            str(binary_path),
            str(source),
        ],
        check=True,
        text=True,
    )
    if not binary_path.exists():
        pytest.skip("ARM64 Mach-O compiler output unavailable")
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze()
        result = RegisterSubstitutionPass(
            {"probability": 1.0, "max_substitutions_per_function": 1, "seed": 1337}
        ).apply(bin_obj)

    expect(CodeSigner().sign(binary_path, adhoc=True), "failed to re-sign mutated Mach-O")
    mutated = run_command([binary_path], text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (mutated.returncode, mutated.stdout, mutated.stderr)
        == (original.returncode, original.stdout, original.stderr)
        == (0, "", ""),
        "ARM64 register substitution changed generated native execution",
    )
