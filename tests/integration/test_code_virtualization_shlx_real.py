"""Native regression for the flag-neutral BMI2 SHLX region handler."""

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


def test_virtualized_shlx_preserves_result_and_flags(tmp_path: Path) -> None:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.exists() or "bmi2" not in cpuinfo.read_text(encoding="utf-8", errors="replace").lower():
        pytest.skip("native SHLX execution requires BMI2")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("native SHLX fixture requires gcc")

    source = tmp_path / "shlx.c"
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    source.write_text(
        r"""
int main(void) {
    unsigned result;
    unsigned char zero;
    __asm__ volatile(
        "cmp $7, %[condition]\n\t"
        "shlx %[count], %[source], %[result]\n\t"
        "sete %[zero]"
        : [result] "=&r" (result), [zero] "=&q" (zero)
        : [condition] "r" (7u), [source] "r" (21u), [count] "r" (1u)
        : "cc");
    return result == 42 && zero ? 42 : 1;
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
    expect(compile_result.returncode == 0, "failed to compile SHLX fixture")
    baseline = run_command([original], timeout=30)
    expect(baseline.returncode == _EXPECTED_EXIT_CODE, "original SHLX fixture returned an unexpected result")
    shutil.copy2(original, mutated)

    with Binary(mutated, writable=True) as binary:
        binary.analyze("aa")
        virtualization_pass = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 5, "seed": 20260919})
        stats = virtualization_pass.apply(binary)
        binary.save()

    transformed = run_command([mutated], timeout=30)
    expect(
        any(
            "shlx" in record.metadata.get("affected_instruction_mnemonics", [])
            for record in virtualization_pass.get_records()
        ),
        f"SHLX instruction was not virtualized: {stats=}",
    )
    expect(transformed.returncode == _EXPECTED_EXIT_CODE, "virtualized SHLX changed the result or condition flags")
