"""Native regression for no-base indexed FP operations in the engine VM."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass, _decode_run_item
from r2morph.mutations.code_virtualization_engine import VirtualizedFpArithMemOp, VirtualizedFpMemOp
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_fpengineidxnb_x86_64"
_EXPECTED_EXIT_CODE = 42

pytestmark = pytest.mark.integration


def test_engine_decodes_no_base_fp_indexed_load() -> None:
    item = _decode_run_item("movsd xmm0, qword ptr [rcx*8 + 0x402000]")

    expect(isinstance(item, VirtualizedFpMemOp) and item.kind == "fploadidxnb")


def test_engine_decodes_no_base_fp_indexed_arithmetic() -> None:
    item = _decode_run_item("addsd xmm0, qword ptr [rcx*8 + 0x402000]")

    expect(isinstance(item, VirtualizedFpArithMemOp) and item.base_index < 0)


def test_engine_no_base_fp_indexed_fixture_uses_fallback_vm(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated_fpidxnb"
    shutil.copyfile(_FIXTURE, mutated)
    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": 20260829}).apply(binary)
        binary.save()
    finally:
        binary.close()

    expect(stats["partial_virtualization_total"] >= 1)
    expect(emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE)
