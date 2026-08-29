"""Real ELF regression for the System V vector-call bridge."""

from __future__ import annotations

import shutil
import stat
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_varargs_x86_64"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not supports_native_elf_x86_64(),
        reason="native ELF x86-64 execution requires Linux amd64",
    ),
]


def test_virtualized_elf_preserves_vector_call_abi(tmp_path: Path) -> None:
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    shutil.copyfile(_FIXTURE, original)
    shutil.copyfile(_FIXTURE, mutated)
    original.chmod(original.stat().st_mode | stat.S_IXUSR)
    mutated.chmod(mutated.stat().st_mode | stat.S_IXUSR)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(stats["functions_virtualized"] >= 1, f"stats={stats}")
    original_result = run_command([str(original)], capture_output=True, timeout=5)
    mutated_result = run_command([str(mutated)], capture_output=True, timeout=5)
    expect(
        (original_result.returncode, mutated_result.returncode) == (69, 69),
        f"original={original_result.returncode}, mutated={mutated_result.returncode}",
    )


def test_virtualized_elf_preserves_ymm_call_abi(tmp_path: Path) -> None:
    source = tmp_path / "ymm_call.c"
    original = tmp_path / "ymm_original"
    mutated = tmp_path / "ymm_mutated"
    source.write_text(r"""
typedef float vector256 __attribute__((vector_size(32)));

__attribute__((noinline)) static vector256 add256(vector256 left, vector256 right) {
    return left + right;
}

int main(void) {
    vector256 left = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    vector256 right = {8.0f, 7.0f, 6.0f, 5.0f, 4.0f, 3.0f, 2.0f, 1.0f};
    vector256 result = add256(left, right);
    return result[0] == 9.0f && result[7] == 9.0f ? 42 : 1;
}
""")
    compile_result = run_command(
        [
            "gcc",
            "-O2",
            "-mavx",
            "-mno-vzeroupper",
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
    expect(compile_result.returncode == 0, "failed to compile the YMM ABI fixture")

    original_result = run_command([original], timeout=30)
    original.rename(mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 20, "seed": 20260833}).apply(binary)
        binary.save()
    finally:
        binary.close()

    mutated_result = run_command([mutated], timeout=30)
    expect(stats["functions_virtualized"] >= 1, f"YMM ABI function was not virtualized: {stats=}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (42, 42),
        f"original={original_result.returncode}, mutated={mutated_result.returncode}, stats={stats}",
    )
