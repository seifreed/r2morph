"""Characterization of Pipeline.run's result contract.

Pins the exact result shape BEFORE the §6 decomposition of the
186-line Pipeline.run, so the decomposition can be proven
behaviour-preserving (CLAUDE.md §5: characterize first, refactor next).

No mocks (§4): a real Binary (fixture ELF) and a real NopInsertionPass
configured to produce zero mutations (deterministic, fast).
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.pipeline.pipeline import Pipeline
from r2morph.utils.logging import logging_context, setup_logging, shutdown_logging
from tests.utils.assertions import expect, expect_all

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
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")
    work_path = tmp_path / "run_contract_sample.bin"
    work_path.write_bytes(binary_path.read_bytes())
    return work_path


def test_empty_pipeline_result_is_exactly_frozen(tmp_path: Path) -> None:
    work_path = _fixture_binary(tmp_path)
    with Binary(work_path) as binary:
        results = Pipeline().run(binary)
    expect(results == {"passes_run": 0, "total_mutations": 0})


def test_single_pass_run_result_contract(tmp_path: Path) -> None:
    work_path = _fixture_binary(tmp_path)
    pipeline = Pipeline()
    nop_pass = NopInsertionPass(config={"probability": 0.0})
    pipeline.add_pass(nop_pass)

    with Binary(work_path) as binary:
        binary.analyze()
        results = pipeline.run(binary)

    expect(set(results.keys()) == EXPECTED_RUN_KEYS)
    expect(set(results["validation"].keys()) == EXPECTED_VALIDATION_KEYS)
    expect(set(results["validation"]["symbolic"].keys()) == EXPECTED_SYMBOLIC_KEYS)
    expect(results["rollback_policy"] == "skip-invalid-pass")
    expect(results["passes_run"] == 1)
    expect(results["total_mutations"] == 0)
    expect(results["failed_passes"] == 0)
    expect(results["rolled_back_passes"] == 0)
    expect(results["mutations"] == [])
    expect(not (nop_pass.name not in results["pass_results"]))
    expect(not (results["validation"]["all_passed"] is not True))


def test_single_pass_run_emits_bounded_correlated_events(tmp_path: Path) -> None:
    work_path = _fixture_binary(tmp_path)
    pipeline = Pipeline()
    nop_pass = NopInsertionPass(config={"probability": 0.0})
    pipeline.add_pass(nop_pass)
    stream = StringIO()
    setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    try:
        with logging_context(correlation_id="pipeline-test", operation="engine.run"), Binary(work_path) as binary:
            binary.analyze()
            pipeline.run(binary)
    finally:
        shutdown_logging()

    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    pass_event = next(event for event in events if event.get("event_name") == "pipeline.pass.completed")
    pipeline_event = next(event for event in events if event.get("event_name") == "pipeline.completed")
    expect_all(
        pass_event["correlation_id"] == "pipeline-test",
        pass_event["pass_name"] == nop_pass.name,
        pass_event["mutation_count"] == 0,
        pass_event["duration_ms"] >= 0,
        pipeline_event["correlation_id"] == "pipeline-test",
        pipeline_event["failed_pass_count"] == 0,
        "mutations" not in pass_event,
    )
