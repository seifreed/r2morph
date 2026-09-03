"""Native regression for ABI return-register substitution."""

from __future__ import annotations

import shutil
import stat
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64
from tests.utils.process import run_command

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not supports_native_elf_x86_64(),
        reason="native ELF x86-64 execution requires Linux amd64",
    ),
]

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_vex128_x86_64"
_EXPECTED_EXIT_CODE = 42


def test_register_substitution_preserves_vex128_fixture_result(tmp_path: Path) -> None:
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    shutil.copyfile(_FIXTURE, original)
    shutil.copyfile(_FIXTURE, mutated)
    original.chmod(original.stat().st_mode | stat.S_IXUSR)
    mutated.chmod(mutated.stat().st_mode | stat.S_IXUSR)

    with Binary(mutated, writable=True) as binary:
        stats = RegisterSubstitutionPass(
            config={"probability": 1.0, "max_substitutions_per_function": 3, "seed": 20260901}
        ).apply(binary)
        binary.save()

    original_result = run_command([str(original)], capture_output=True, timeout=30)
    mutated_result = run_command([str(mutated)], capture_output=True, timeout=30)
    expect(stats["mutations_applied"] > 0, f"stats={stats}")
    expect(
        (original_result.returncode, mutated_result.returncode) == (_EXPECTED_EXIT_CODE, _EXPECTED_EXIT_CODE),
        f"original={original_result.returncode}, mutated={mutated_result.returncode}",
    )
