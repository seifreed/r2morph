import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect
from tests.utils.process import run_command


def test_nop_insertion_pe_x86_64_preserves_repaired_integrity(tmp_path: Path) -> None:
    compiler = shutil.which("x86_64-w64-mingw32-gcc")
    wine = shutil.which("wine")
    if compiler is None or wine is None:
        pytest.skip("PE compiler and Wine runtime are required")

    source = tmp_path / "nop_sample.c"
    source.write_text(
        "#include <stdint.h>\n"
        "__attribute__((noinline)) int transform(int value) {\n"
        "  volatile uint32_t cell = (uint32_t)value;\n"
        "  if ((cell & 1U) != 0U) {\n"
        "    cell = cell * 3U + 2U;\n"
        "  } else {\n"
        "    cell = cell / 2U;\n"
        "  }\n"
        '  __asm__ volatile("mov %%eax, %%eax\\n" : "+a"(value));\n'
        "  return (int)(cell ^ (uint32_t)value);\n"
        "}\n"
        "int main(void) { return transform(41) != 84; }\n"
    )
    binary_path = tmp_path / "nop_sample.exe"
    run_command([compiler, "-O0", "-fno-inline", "-o", str(binary_path), str(source)], check=True)
    original_execution = run_command([wine, str(binary_path)], timeout=30)
    expect(
        original_execution.returncode == 0,
        f"generated PE fixture did not execute successfully: {original_execution.returncode}",
    )

    handler = PEHandler(binary_path)
    expect(handler.fix_checksum())
    expect(handler.validate_integrity()[0])

    with Binary(binary_path, writable=True) as binary:
        binary.analyze("aaa")
        result = NopInsertionPass(
            {
                "probability": 1.0,
                "max_nops_per_function": 2,
                "use_creative_nops": False,
                "seed": 1337,
            }
        ).apply(binary)

    expect(result["mutations_applied"] > 0)
    expect(handler.fix_checksum())
    expect(handler.validate_integrity()[0])

    mutated_execution = run_command([wine, str(binary_path)], timeout=30)
    expect(
        mutated_execution.returncode == original_execution.returncode == 0,
        "PE NOP insertion changed the native execution result",
    )


def test_instruction_substitution_pe_x86_64_preserves_native_execution(tmp_path: Path) -> None:
    compiler = shutil.which("x86_64-w64-mingw32-gcc")
    wine = shutil.which("wine")
    if compiler is None or wine is None:
        pytest.skip("PE compiler and Wine runtime are required")

    source = tmp_path / "substitution_sample.c"
    source.write_text(
        "#include <stdint.h>\n"
        "__attribute__((noinline)) int transform(int value) {\n"
        "  volatile uint32_t cell = (uint32_t)value;\n"
        "  if ((cell & 1U) != 0U) {\n"
        "    cell = cell * 3U + 2U;\n"
        "  } else {\n"
        "    cell = cell / 2U;\n"
        "  }\n"
        '  __asm__ volatile("mov %%eax, %%eax\\n" : "+a"(value));\n'
        "  return (int)(cell ^ (uint32_t)value);\n"
        "}\n"
        "int main(void) { return transform(41) != 84; }\n"
    )
    binary_path = tmp_path / "substitution_sample.exe"
    run_command([compiler, "-O0", "-fno-inline", "-o", str(binary_path), str(source)], check=True)
    original_execution = run_command([wine, str(binary_path)], timeout=30)
    expect(original_execution.returncode == 0, "generated PE fixture did not execute successfully")

    handler = PEHandler(binary_path)
    with Binary(binary_path, writable=True) as binary:
        binary.analyze("aa")
        result = InstructionSubstitutionPass({"probability": 1.0, "force_different": True, "seed": 1337}).apply(binary)

    expect(result["mutations_applied"] > 0)
    expect(handler.fix_checksum())
    expect(handler.validate_integrity()[0])

    mutated_execution = run_command([wine, str(binary_path)], timeout=30)
    expect(
        mutated_execution.returncode == original_execution.returncode == 0,
        "PE instruction substitution changed the native execution result",
    )


def test_register_substitution_pe_x86_64_preserves_native_execution(tmp_path: Path) -> None:
    compiler = shutil.which("x86_64-w64-mingw32-gcc")
    wine = shutil.which("wine")
    if compiler is None or wine is None:
        pytest.skip("PE compiler and Wine runtime are required")

    source = tmp_path / "register_sample.c"
    source.write_text(
        "#include <stdint.h>\n"
        "__attribute__((noinline)) int transform(int value) {\n"
        "  volatile uint32_t cell = (uint32_t)value;\n"
        "  if ((cell & 1U) != 0U) {\n"
        "    cell = cell * 3U + 2U;\n"
        "  } else {\n"
        "    cell = cell / 2U;\n"
        "  }\n"
        '  __asm__ volatile("mov %%eax, %%eax\\n" : "+a"(value));\n'
        "  return (int)(cell ^ (uint32_t)value);\n"
        "}\n"
        "int main(void) { return transform(41) != 84; }\n"
    )
    binary_path = tmp_path / "register_sample.exe"
    run_command([compiler, "-O0", "-fno-inline", "-o", str(binary_path), str(source)], check=True)
    original_execution = run_command([wine, str(binary_path)], timeout=30)
    expect(original_execution.returncode == 0, "generated PE fixture did not execute successfully")

    handler = PEHandler(binary_path)
    with Binary(binary_path, writable=True) as binary:
        binary.analyze("aa")
        result = RegisterSubstitutionPass({"probability": 1.0, "seed": 1337}).apply(binary)

    expect(result["mutations_applied"] > 0)
    expect(handler.fix_checksum())
    expect(handler.validate_integrity()[0])

    mutated_execution = run_command([wine, str(binary_path)], timeout=30)
    expect(
        mutated_execution.returncode == original_execution.returncode == 0,
        "PE register substitution changed the native execution result",
    )
