"""Native regression for scalar and legacy GP/XMM movq transfers."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64

_FIXTURE = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset" / "elf_vm_movq_x86_64"
_EXPECTED_EXIT_CODE = 42

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not supports_native_elf_x86_64(),
        reason="native ELF x86-64 execution requires Linux amd64",
    ),
]


def test_movq_fixture_original_has_expected_exit_code() -> None:
    expect(emulate_exit_code(_FIXTURE) == _EXPECTED_EXIT_CODE)


def test_movq_fixture_classifies_legacy_gp_to_xmm_transfer() -> None:
    with Binary(_FIXTURE) as binary:
        binary.analyze()
        instructions = binary.get_function_disasm(int(binary.get_functions()[0]["addr"]))

    transfer = next(instruction for instruction in instructions if "movq xmm3" in instruction.get("opcode", ""))
    expect(transfer.get("opcode", "").startswith("movq xmm3, r8"))


def test_movq_fixture_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated-movq"
    shutil.copyfile(_FIXTURE, mutated)
    with Binary(mutated, writable=True) as binary:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260828}).apply(binary)
        binary.save()

    expect(stats["functions_virtualized"] >= 1)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)
