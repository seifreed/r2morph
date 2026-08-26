"""Run a bounded mutation-fuzzer campaign against a real transformed ELF."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.validation.mutation_fuzzer import MutationPassFuzzer
from r2morph.validation.mutation_fuzzer_types import FuzzConfig
from tests.utils.assertions import expect

_DATASET = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset"
_FIXTURE = _DATASET / "elf_vm_arith_x86_64"
_FUZZ_CASES = 3
_FUZZ_SEED = 20260826
_FUZZ_TIMEOUT_SECONDS = 2

pytestmark = pytest.mark.integration


def test_mutation_fuzzer_real_campaign_preserves_transformed_fixture(tmp_path: Path) -> None:
    original = tmp_path / "original"
    mutated = tmp_path / "mutated"
    shutil.copyfile(_FIXTURE, original)
    shutil.copyfile(_FIXTURE, mutated)

    binary = Binary(mutated, writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0, "seed": _FUZZ_SEED}).apply(binary)
        binary.save()
    finally:
        binary.close()

    campaign = MutationPassFuzzer(
        FuzzConfig(
            num_tests=_FUZZ_CASES,
            timeout=_FUZZ_TIMEOUT_SECONDS,
            seed=_FUZZ_SEED,
            save_failing_cases=False,
        )
    ).fuzz_mutations(original, mutated, ["code-virtualization"])

    expect(campaign.total_tests == _FUZZ_CASES)
    expect(campaign.failed == 0, f"campaign={campaign.to_dict()!r}")
