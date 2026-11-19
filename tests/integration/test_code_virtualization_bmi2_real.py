"""Native regressions for flag-neutral BMI2 region handlers."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

_EXPECTED_EXIT_CODE = 42
pytestmark = pytest.mark.skipif(
    not supports_native_elf_x86_64(),
    reason="native SHLX virtualization requires Linux x86-64",
)


def test_virtualized_bmi2_shifts_preserve_results_and_flags(tmp_path: Path) -> None:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.exists() or "bmi2" not in cpuinfo.read_text(encoding="utf-8", errors="replace").lower():
        pytest.skip("native BMI2 execution requires BMI2")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("native SHLX fixture requires gcc")

    source = tmp_path / "bmi2.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(
        r"""
int main(void) {
    unsigned result, rotated;
    unsigned char zero, rotate_zero;
    __asm__ volatile(
        "cmp $7, %[condition]\n\t"
        "shlx %[count], %[source], %[result]\n\t"
        "sete %[zero]\n\t"
        "cmp $7, %[condition]\n\t"
        "rorx $2, %[rotate_source], %[rotated]\n\t"
        "sete %[rotate_zero]"
        : [result] "=&r" (result), [zero] "=&q" (zero), [rotated] "=&r" (rotated),
          [rotate_zero] "=&q" (rotate_zero)
        : [condition] "r" (7u), [source] "r" (21u), [count] "r" (1u), [rotate_source] "r" (168u)
        : "cc");
    return result == 42 && zero && rotated == 42 && rotate_zero ? 42 : 1;
}
""",
        encoding="utf-8",
    )
    compile_result = run_command(
        [
            compiler,
            "-O1",
            "-mbmi2",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            source,
            "-o",
            original,
        ],
        timeout=30,
    )
    expect(compile_result.returncode == 0, "failed to compile BMI2 fixture")
    baseline = run_command([original], timeout=30)
    expect(baseline.returncode == _EXPECTED_EXIT_CODE, "original BMI2 fixture returned an unexpected result")
    shutil.copy2(original, mutated)

    with Binary(mutated, writable=True) as binary:
        binary.analyze("aa")
        virtualization_pass = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 5, "seed": 20260919})
        stats = virtualization_pass.apply(binary)
        binary.save()

    transformed = run_command([mutated], timeout=30)
    affected = {
        mnemonic
        for record in virtualization_pass.get_records()
        for mnemonic in record.metadata.get("affected_instruction_mnemonics", [])
    }
    expect(
        {"shlx", "rorx"} <= affected,
        f"SHLX and RORX were not both virtualized: {stats=}",
    )
    expect(transformed.returncode == _EXPECTED_EXIT_CODE, "virtualized BMI2 shifts changed results or condition flags")
