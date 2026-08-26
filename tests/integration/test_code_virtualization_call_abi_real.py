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
