"""Real ELF regression for callee stack cleanup on an internal return."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

pytestmark = pytest.mark.integration

_EXPECTED_EXIT_CODE = 42
_SOURCE = r"""
.text
.globl main
.type main, @function
main:
    pushq $0
    call .Lcallee
    movl $42, %eax
    ret
.Lcallee:
    movl $42, %eax
    ret $8
.size main, .-main
"""


def _compile_fixture(tmp_path: Path) -> Path:
    source = tmp_path / "ret_immediate.S"
    binary = tmp_path / "ret_immediate"
    source.write_text(_SOURCE)
    result = run_command(
        [
            "gcc",
            "-fno-pie",
            "-no-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            source,
            "-o",
            binary,
        ],
        timeout=30,
    )
    expect(result.returncode == 0, "failed to compile the ret-immediate fixture")
    return binary


def test_virtualized_internal_ret_immediate_preserves_exit_code(tmp_path: Path) -> None:
    if not supports_native_elf_x86_64():
        pytest.skip("the regression requires Linux amd64 ELF execution")
    if shutil.which("gcc") is None:
        pytest.skip("fixture requires gcc")
    original = _compile_fixture(tmp_path)
    mutated = tmp_path / "ret_immediate_mutated"
    shutil.copy2(original, mutated)
    original_result = run_command([original], timeout=30)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260831}).apply(binary)
        binary.save()
    finally:
        binary.close()

    mutated_result = run_command([mutated], timeout=30)
    expect(
        stats["functions_virtualized"] >= 1
        and (original_result.returncode, mutated_result.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE),
        "ret-immediate semantics changed: "
        f"{stats=}, original={original_result.returncode}, mutated={mutated_result.returncode}",
    )
