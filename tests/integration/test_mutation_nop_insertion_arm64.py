import platform
import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.platform.codesign import CodeSigner
from tests.utils.assertions import expect
from tests.utils.process import run_command


def _build_arm64_return_binary(tmp_path: Path, return_code: int) -> Path:
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("clang not available")
    source = tmp_path / f"arm64_return_{return_code}.c"
    source.write_text(f"int main(void) {{ return {return_code}; }}\n")
    binary_path = tmp_path / f"arm64_return_{return_code}"
    run_command(
        [clang, "-arch", "arm64", "-O0", "-fno-inline", "-o", str(binary_path), str(source)],
        check=True,
        text=True,
    )
    return binary_path


def _build_arm64_control_flow_binary(tmp_path: Path) -> Path:
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("clang not available")
    source = tmp_path / "arm64_control_flow.c"
    source.write_text(
        "#include <stdint.h>\n"
        "__attribute__((noinline)) int transform(int value) {\n"
        "    volatile uint32_t cell = (uint32_t)value;\n"
        "    if ((cell & 1U) != 0U) {\n"
        "        cell = cell * 3U + 2U;\n"
        "    } else {\n"
        "        cell = cell / 2U;\n"
        "    }\n"
        "    return (int)(cell ^ 0x5aU);\n"
        "}\n"
        "int main(void) { return transform(7) == 77 ? 0 : 1; }\n"
    )
    binary_path = tmp_path / "arm64_control_flow"
    run_command(
        [clang, "-arch", "arm64", "-O0", "-fno-inline", "-o", str(binary_path), str(source)],
        check=True,
        text=True,
    )
    return binary_path


def test_nop_insertion_arm64_path(tmp_path: Path):
    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "macho_arm64_nop"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0})
        result = pass_obj.apply(bin_obj)

    expect(not ("mutations_applied" not in result))


def test_nop_insertion_arm64_preserves_native_output(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("Mach-O arm64 execution requires macOS")

    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "macho_arm64_runtime"
    shutil.copy(binary_path, temp_binary)
    original = run_command([temp_binary], text=True, timeout=30)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        result = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0, "seed": 1337}).apply(bin_obj)

    expect(CodeSigner().sign(temp_binary, adhoc=True), "failed to re-sign mutated Mach-O")
    mutated = run_command([temp_binary], text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (mutated.returncode, mutated.stdout, mutated.stderr)
        == (original.returncode, original.stdout, original.stderr)
        == (0, "hello\n", ""),
        "ARM64 Mach-O NOP insertion changed native execution",
    )


def test_nop_insertion_arm64_does_not_record_encoding_identical_rewrites(tmp_path: Path):
    """ARM64 zero-immediate replacement must change bytes without false records."""
    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "macho_arm64_noop"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = NopInsertionPass(config={"max_nops_per_function": 2, "probability": 1.0})
        result = pass_obj.apply(bin_obj)

    noop_records = [r for r in pass_obj._records if r.original_bytes == r.mutated_bytes]
    expect(noop_records == [])
    expect(result["mutations_applied"] > 0)
    expect(result["mutations_applied"] == len(pass_obj._records))


def test_instruction_substitution_arm64_changes_real_instruction_encoding(tmp_path: Path):
    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "macho_arm64_substitution"
    shutil.copy(binary_path, temp_binary)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        candidate = next(
            instruction
            for function in bin_obj.get_functions()
            for instruction in bin_obj.get_function_disasm(function["addr"])
            if instruction.get("disasm", "").startswith("mov w0, 0")
        )
        original_bytes = bin_obj.read_bytes(candidate["addr"], candidate["size"])
        result = InstructionSubstitutionPass({"max_substitutions_per_function": 1, "probability": 1.0}).apply(bin_obj)
        mutated_bytes = bin_obj.read_bytes(candidate["addr"], candidate["size"])

    expect(result["mutations_applied"] > 0)
    expect(mutated_bytes != original_bytes)


def test_instruction_substitution_arm64_preserves_native_output(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("Mach-O arm64 execution requires macOS")

    binary_path = Path("fixtures/dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O binary not available")

    temp_binary = tmp_path / "macho_arm64_substitution_runtime"
    shutil.copy(binary_path, temp_binary)
    original = run_command([temp_binary], text=True, timeout=30)

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        result = InstructionSubstitutionPass(
            {"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        ).apply(bin_obj)

    expect(CodeSigner().sign(temp_binary, adhoc=True), "failed to re-sign mutated Mach-O")
    mutated = run_command([temp_binary], text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (mutated.returncode, mutated.stdout, mutated.stderr)
        == (original.returncode, original.stdout, original.stderr)
        == (0, "hello\n", ""),
        "ARM64 instruction substitution changed native execution",
    )


def test_instruction_substitution_arm64_compiled_binary_preserves_return_code(tmp_path: Path):
    if platform.system() != "Darwin":
        pytest.skip("Mach-O arm64 execution requires macOS")

    binary_path = _build_arm64_return_binary(tmp_path, 3)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze()
        result = InstructionSubstitutionPass(
            {"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        ).apply(bin_obj)

    expect(CodeSigner().sign(binary_path, adhoc=True), "failed to re-sign mutated Mach-O")
    mutated = run_command([binary_path], text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (mutated.returncode, mutated.stdout, mutated.stderr)
        == (original.returncode, original.stdout, original.stderr)
        == (3, "", ""),
        "ARM64 substitution changed a compiled binary return code",
    )


def test_instruction_substitution_arm64_compiled_binary_rejects_unrepresentable_immediate(
    tmp_path: Path,
):
    if platform.system() != "Darwin":
        pytest.skip("Mach-O arm64 execution requires macOS")

    binary_path = _build_arm64_return_binary(tmp_path, 37)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze()
        result = InstructionSubstitutionPass(
            {"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        ).apply(bin_obj)

    mutated = run_command([binary_path], text=True, timeout=30)
    expect(
        result["mutations_applied"] == 0
        and (mutated.returncode, mutated.stdout, mutated.stderr)
        == (original.returncode, original.stdout, original.stderr)
        == (37, "", ""),
        "ARM64 substitution did not fail closed for an unrepresentable immediate",
    )


def test_instruction_substitution_arm64_preserves_compiled_control_flow_and_memory(
    tmp_path: Path,
):
    if platform.system() != "Darwin":
        pytest.skip("Mach-O arm64 execution requires macOS")

    binary_path = _build_arm64_control_flow_binary(tmp_path)
    original = run_command([binary_path], text=True, timeout=30)

    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze()
        result = InstructionSubstitutionPass(
            {"max_substitutions_per_function": 1, "probability": 1.0, "seed": 1337}
        ).apply(bin_obj)

    expect(CodeSigner().sign(binary_path, adhoc=True), "failed to re-sign mutated Mach-O")
    mutated = run_command([binary_path], text=True, timeout=30)
    expect(
        result["mutations_applied"] > 0
        and (mutated.returncode, mutated.stdout, mutated.stderr)
        == (original.returncode, original.stdout, original.stderr)
        == (0, "", ""),
        "ARM64 substitution changed compiled control-flow or memory semantics",
    )
