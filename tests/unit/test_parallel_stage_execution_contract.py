from __future__ import annotations

import json
import logging
from io import StringIO

from r2morph.core.parallel_planner import PassResult, PassStatus
from r2morph.core.parallel_stage_execution import execute_stage
from r2morph.protocols import MutationPassProtocol
from r2morph.utils.logging import logging_context, setup_logging, shutdown_logging
from tests.utils.assertions import expect, expect_all
from tests.utils.field_names import MUTATION_NAME_KEY


class _Pass:
    def __init__(self, name: str) -> None:
        self.name = name


def test_parallel_stage_execution_runs_known_passes() -> None:
    seen: list[str] = []

    def execute_pass(pass_obj: MutationPassProtocol, progress_callback):
        seen.append(pass_obj.name)
        return PassResult(**{MUTATION_NAME_KEY: pass_obj.name}, status=PassStatus.COMPLETED)

    results = execute_stage(
        ["one", "missing", "two"],
        [_Pass("one"), _Pass("two")],
        max_workers=2,
        execute_pass=execute_pass,
        progress_callback=None,
    )

    expect(set(results) == {"one", "two"})
    expect(all(result.status == PassStatus.COMPLETED for result in results.values()))
    expect(sorted(seen) == ["one", "two"])


def test_parallel_stage_execution_propagates_logging_context() -> None:
    stream = StringIO()
    setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})
    logger = logging.getLogger("r2morph.parallel-stage-test")

    def execute_pass(pass_obj: MutationPassProtocol, progress_callback):
        logger.info("Executed %s", pass_obj.name)
        return PassResult(**{MUTATION_NAME_KEY: pass_obj.name}, status=PassStatus.COMPLETED)

    try:
        with logging_context(correlation_id="parallel-17", operation="pipeline.parallel"):
            results = execute_stage(
                ["one", "two"],
                [_Pass("one"), _Pass("two")],
                max_workers=2,
                execute_pass=execute_pass,
                progress_callback=None,
            )
    finally:
        shutdown_logging()

    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    expect_all(
        set(results) == {"one", "two"},
        {event["correlation_id"] for event in events} == {"parallel-17"},
        {event["operation"] for event in events} == {"pipeline.parallel"},
    )
