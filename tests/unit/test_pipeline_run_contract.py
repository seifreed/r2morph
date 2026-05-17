"""Characterization of Pipeline.run's result contract.

Pins the exact result shape BEFORE the §6 decomposition of the
186-line Pipeline.run, so the decomposition can be proven
behaviour-preserving (CLAUDE.md §5: characterize first, refactor next).

No mocks (§4): a real Binary (fixture ELF) and a real NopInsertionPass
configured to produce zero mutations (deterministic, fast).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.pipeline.pipeline import Pipeline

EXPECTED_RUN_KEYS = {
    "passes_run",
    "total_mutations",
    "rolled_back_passes",
    "failed_passes",
    "discarded_mutations",
    "discarded_mutations_detail",
    "pass_results",
    "mutations",
    "validation",
    "rollback_policy",
}
EXPECTED_VALIDATION_KEYS = {
    "passes",
    "all_passed",
    "failed_passes",
    "total_issues",
    "runtime_passes",
    "symbolic",
}
EXPECTED_SYMBOLIC_KEYS = {
    "requested",
    "proven",
    "supported_passes",
    "fallback_passes",
    "statuses",
}


def _fixture_binary(tmp_path: Path) -> Path:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")
    work_path = tmp_path / "run_contract_sample.bin"
    work_path.write_bytes(binary_path.read_bytes())
    return work_path


def test_empty_pipeline_result_is_exactly_frozen(tmp_path: Path) -> None:
    work_path = _fixture_binary(tmp_path)
    with Binary(work_path) as binary:
        results = Pipeline().run(binary)
    assert results == {"passes_run": 0, "total_mutations": 0}


def test_single_pass_run_result_contract(tmp_path: Path) -> None:
    work_path = _fixture_binary(tmp_path)
    pipeline = Pipeline()
    nop_pass = NopInsertionPass(config={"probability": 0.0})
    pipeline.add_pass(nop_pass)

    with Binary(work_path) as binary:
        binary.analyze()
        results = pipeline.run(binary)

    assert set(results.keys()) == EXPECTED_RUN_KEYS
    assert set(results["validation"].keys()) == EXPECTED_VALIDATION_KEYS
    assert set(results["validation"]["symbolic"].keys()) == EXPECTED_SYMBOLIC_KEYS
    assert results["rollback_policy"] == "skip-invalid-pass"
    assert results["passes_run"] == 1
    assert results["total_mutations"] == 0
    assert results["failed_passes"] == 0
    assert results["rolled_back_passes"] == 0
    assert results["mutations"] == []
    assert nop_pass.name in results["pass_results"]
    assert results["validation"]["all_passed"] is True
