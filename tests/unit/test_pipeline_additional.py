from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.pipeline.pipeline import Pipeline


def test_pipeline_basic_lifecycle() -> None:
    pipeline = Pipeline()
    assert len(pipeline) == 0
    assert pipeline.get_pass_names() == []
    assert "Pipeline" in repr(pipeline)

    nop_pass = NopInsertionPass(config={"probability": 0.0})
    pipeline.add_pass(nop_pass)
    assert len(pipeline) == 1
    assert pipeline.get_pass_names() == [nop_pass.name]

    assert pipeline.remove_pass(nop_pass.name) is True
    assert pipeline.remove_pass("missing") is False
    pipeline.clear()
    assert len(pipeline) == 0


def test_pipeline_run_with_real_pass(tmp_path: Path) -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(binary_path.read_bytes())

    pipeline = Pipeline()
    nop_pass = NopInsertionPass(config={"probability": 0.0})
    pipeline.add_pass(nop_pass)

    with Binary(work_path) as binary:
        binary.analyze()
        results = pipeline.run(binary)

    assert results["passes_run"] == 1
    assert "pass_results" in results
    assert nop_pass.name in results["pass_results"]


def test_pipeline_run_empty(tmp_path: Path) -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(binary_path.read_bytes())

    pipeline = Pipeline()
    with Binary(work_path) as binary:
        binary.analyze()
        results = pipeline.run(binary)

    assert results["passes_run"] == 0
    assert results["total_mutations"] == 0
