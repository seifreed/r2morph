"""Production logging contracts using real handlers and files."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from r2morph.adapters.process import run_process
from r2morph.utils.logging import (
    _MAX_COLLECTION_ITEMS,
    LoggingConfig,
    ProcessOwnerFilter,
    _safe_value,
    logging_context,
    observed_operation,
    setup_logging,
    shutdown_logging,
)
from tests.utils.assertions import expect, expect_all

_EXPECTED_CONCURRENT_EVENT_COUNT_80 = 80
_EXPECTED_CORRELATION_ID_LENGTH_32 = 32
_EXPECTED_DURATION_MS_12_5 = 12.5
_EXPECTED_MAX_RETAINED_FILES_3 = 3
_EXPECTED_MAX_BYTES_2048 = 2048
_EXPECTED_BACKUP_COUNT_3 = 3
_MAX_SAFE_MESSAGE_LENGTH_4200 = 4200


class _IterationBoundedMapping(Mapping[str, str]):
    def __getitem__(self, key: str) -> str:
        return key

    def __iter__(self) -> Iterator[str]:
        yield from (str(index) for index in range(_MAX_COLLECTION_ITEMS + 1))
        raise AssertionError("mapping iteration exceeded the logging collection cap")

    def __len__(self) -> int:
        return _MAX_COLLECTION_ITEMS + 1


class _IterationBoundedList(list[str]):
    def __iter__(self) -> Iterator[str]:
        yield from (str(index) for index in range(_MAX_COLLECTION_ITEMS + 1))
        raise AssertionError("list iteration exceeded the logging collection cap")

    def __len__(self) -> int:
        return _MAX_COLLECTION_ITEMS + 1


@pytest.fixture(autouse=True)
def close_logging_handlers_after_test() -> Any:
    yield
    shutdown_logging()


def _json_events(stream: StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_setup_logging_production_environment_emits_normalized_json() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={"R2MORPH_ENVIRONMENT": "production"})

    logger.info(
        "Pipeline finished",
        extra={
            "event_name": "pipeline.completed",
            "operation": "pipeline.run",
            "duration_ms": 12.5,
            "outcome": "success",
        },
    )

    event = _json_events(stream)[0]
    expect_all(
        event["timestamp"].endswith("Z"),
        event["level"] == "INFO",
        event["message"] == "Pipeline finished",
        event["service"] == "r2morph",
        event["component"] == "r2morph",
        event["environment"] == "production",
        event["process_id"] == os.getpid(),
        event["thread_name"] == "MainThread",
        event["event_name"] == "pipeline.completed",
        event["operation"] == "pipeline.run",
        event["duration_ms"] == _EXPECTED_DURATION_MS_12_5,
        event["outcome"] == "success",
    )


def test_setup_logging_rejects_invalid_level() -> None:
    with pytest.raises(ValueError, match="Invalid log level"):
        setup_logging(level="verbose", stream=StringIO(), environ={})


def test_setup_logging_selects_requested_level() -> None:
    stream = StringIO()
    logger = setup_logging(
        level="WARNING",
        stream=stream,
        environ={"R2MORPH_LOG_FORMAT": "json"},
    )

    logger.info("not emitted")
    logger.warning("emitted")

    events = _json_events(stream)
    expect(len(events) == 1 and events[0]["message"] == "emitted")


def test_logging_context_adds_correlation_without_leaking_between_operations() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    with logging_context(correlation_id="job-123", operation="engine.run"):
        logger.info("inside")
    logger.info("outside")

    inside, outside = _json_events(stream)
    expect_all(
        inside["correlation_id"] == "job-123",
        inside["operation"] == "engine.run",
        "correlation_id" not in outside,
        "operation" not in outside,
    )


def test_console_format_includes_bound_correlation() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={})

    with logging_context(correlation_id="console-3", operation="binary.open"):
        logger.info("Opened")

    expect("correlation_id=console-3 operation=binary.open" in stream.getvalue())


def test_process_owner_filter_rejects_inherited_handler_record() -> None:
    record = logging.makeLogRecord({})

    expect(ProcessOwnerFilter(os.getpid()).filter(record) and not ProcessOwnerFilter(os.getpid() + 1).filter(record))


def test_shutdown_logging_restores_library_logger_defaults() -> None:
    logger = setup_logging(stream=StringIO(), environ={})

    shutdown_logging()

    expect(not logger.handlers and logger.level == logging.NOTSET and logger.propagate)


def test_logging_context_propagates_to_async_task() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    async def emit_from_task() -> None:
        logger.info("async event")

    async def run() -> None:
        with logging_context(correlation_id="async-42", operation="analysis.run"):
            await asyncio.create_task(emit_from_task())

    asyncio.run(run())

    event = _json_events(stream)[0]
    expect(event["correlation_id"] == "async-42" and event["operation"] == "analysis.run")


def test_observed_operation_records_duration_and_outcome() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    with observed_operation(logger, "pipeline.run", event_name="pipeline") as correlation_id:
        expect(len(correlation_id) == _EXPECTED_CORRELATION_ID_LENGTH_32)

    event = _json_events(stream)[0]
    expect_all(
        event["event_name"] == "pipeline.completed",
        event["operation"] == "pipeline.run",
        event["outcome"] == "success",
        event["duration_ms"] >= 0,
        event["correlation_id"] == correlation_id,
    )


def test_observed_operation_records_exception_without_changing_it() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    with (
        pytest.raises(ValueError, match="invalid input"),
        observed_operation(
            logger,
            "pipeline.run",
            event_name="pipeline",
        ),
    ):
        raise ValueError("invalid input")

    event = _json_events(stream)[0]
    expect_all(
        event["event_name"] == "pipeline.failed",
        event["outcome"] == "failure",
        event["error_type"] == "ValueError",
        "ValueError: invalid input" in event["stack_trace"],
    )


def test_nested_observed_operations_emit_one_traceback() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    with (
        pytest.raises(RuntimeError, match="nested failure"),
        observed_operation(
            logger,
            "workflow.run",
            event_name="workflow",
        ),
        observed_operation(logger, "engine.run", event_name="engine"),
    ):
        raise RuntimeError("nested failure")

    events = _json_events(stream)
    expect_all(
        [event["event_name"] for event in events] == ["engine.failed", "workflow.failed"],
        sum("stack_trace" in event for event in events) == 1,
        {event["error_type"] for event in events} == {"RuntimeError"},
        len({event["correlation_id"] for event in events}) == 1,
    )


def test_formatter_redacts_secrets_paths_and_control_characters() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    logger.error("password=hunter2 Authorization: Bearer abc.def file=/Users/analyst/samples/input.bin\nforged")

    message = _json_events(stream)[0]["message"]
    expect_all(
        "hunter2" not in message,
        "abc.def" not in message,
        "/Users/analyst" not in message,
        "<path:input.bin>" in message,
        "\n" not in message,
        r"\n" in message,
    )


def test_formatter_redacts_compound_secret_assignments() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    logger.error("client_secret=alpha secret_key=beta private_key=gamma oauth_token=delta id_token=epsilon")

    message = _json_events(stream)[0]["message"]
    expect(
        message == "client_secret=<redacted> secret_key=<redacted> private_key=<redacted> "
        "oauth_token=<redacted> id_token=<redacted>"
    )


def test_formatter_bounds_untrusted_message_size() -> None:
    stream = StringIO()
    logger = setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    logger.error("x" * 10000)

    message = _json_events(stream)[0]["message"]
    expect(len(message) < _MAX_SAFE_MESSAGE_LENGTH_4200 and message.endswith("<truncated:5904>"))


def test_safe_value_bounds_mapping_iteration() -> None:
    safe_mapping = _safe_value(_IterationBoundedMapping())

    expect(
        safe_mapping
        == {
            **{str(index): str(index) for index in range(_MAX_COLLECTION_ITEMS)},
            "_truncated_items": 1,
        }
    )


def test_safe_value_redacts_secret_assignments_in_mapping_keys() -> None:
    safe_mapping = _safe_value({"password=hunter2": "private"})

    expect(json.dumps(safe_mapping) == '{"password=<redacted>": "<redacted>"}')


def test_safe_value_redacts_compound_secret_field_names() -> None:
    safe_mapping = _safe_value(
        {
            "client_secret": "alpha",
            "secret_key": "beta",
            "oauth-token": "gamma",
            "id_token": "delta",
        }
    )

    expect(
        safe_mapping
        == {
            "client_secret": "<redacted>",
            "secret_key": "<redacted>",
            "oauth-token": "<redacted>",
            "id_token": "<redacted>",
        }
    )


def test_safe_value_sanitizes_path_basename() -> None:
    safe_path = _safe_value(Path("token=pathsecret\nforged"))

    expect(safe_path == "<path:token=<redacted>\\nforged>")


def test_safe_value_bounds_sequence_iteration() -> None:
    safe_values = _safe_value(_IterationBoundedList())

    expect(
        safe_values
        == [
            *[str(index) for index in range(_MAX_COLLECTION_ITEMS)],
            "<truncated:1>",
        ]
    )


def _write_concurrent_events(logger: logging.Logger, worker_id: int) -> None:
    with logging_context(correlation_id=f"worker-{worker_id}", operation="parallel.run"):
        for sequence in range(10):
            logger.info(
                "Worker event",
                extra={"event_name": "parallel.progress", "status": sequence},
            )


def test_file_logging_is_thread_safe_and_preserves_json_records(tmp_path: Path) -> None:
    log_path = tmp_path / "concurrent.jsonl"
    logger = setup_logging(
        log_file=log_path,
        stream=StringIO(),
        environ={"R2MORPH_LOG_FORMAT": "json"},
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda worker_id: _write_concurrent_events(logger, worker_id), range(8)))
    shutdown_logging()

    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    correlation_ids = {event["correlation_id"] for event in events}
    expect(
        len(events) == _EXPECTED_CONCURRENT_EVENT_COUNT_80
        and correlation_ids == {f"worker-{worker_id}" for worker_id in range(8)}
    )


def test_file_logging_rotates_with_bounded_retention(tmp_path: Path) -> None:
    log_path = tmp_path / "rotating.jsonl"
    logger = setup_logging(
        log_file=log_path,
        stream=StringIO(),
        environ={
            "R2MORPH_LOG_FORMAT": "json",
            "R2MORPH_LOG_MAX_BYTES": "400",
            "R2MORPH_LOG_BACKUP_COUNT": "2",
        },
    )

    for sequence in range(30):
        logger.info("Rotation event %s with bounded payload", sequence)
    shutdown_logging()

    retained = sorted(tmp_path.glob("rotating.jsonl*"))
    expect(log_path in retained and 1 < len(retained) <= _EXPECTED_MAX_RETAINED_FILES_3)


def test_unavailable_file_destination_degrades_to_console(tmp_path: Path) -> None:
    stream = StringIO()
    logger = setup_logging(
        log_file=tmp_path,
        stream=stream,
        environ={"R2MORPH_LOG_FORMAT": "json"},
    )

    logger.info("Application remains available")

    events = _json_events(stream)
    expect(
        len(logger.handlers) == 1
        and events[0]["event_name"] == "logging.destination_unavailable"
        and events[1]["message"] == "Application remains available"
    )


def test_logging_config_reads_environment_without_global_mutation(tmp_path: Path) -> None:
    config = LoggingConfig.from_environment(
        {
            "R2MORPH_LOG_LEVEL": "error",
            "R2MORPH_LOG_FORMAT": "json",
            "R2MORPH_ENVIRONMENT": "staging",
            "R2MORPH_LOG_FILE": str(tmp_path / "events.jsonl"),
            "R2MORPH_LOG_MAX_BYTES": "2048",
            "R2MORPH_LOG_BACKUP_COUNT": "3",
        }
    )

    expect_all(
        config.level == "ERROR",
        config.format_name == "json",
        config.environment == "staging",
        config.log_file == tmp_path / "events.jsonl",
        config.max_bytes == _EXPECTED_MAX_BYTES_2048,
        config.backup_count == _EXPECTED_BACKUP_COUNT_3,
    )


def test_process_adapter_emits_correlated_completion_without_arguments() -> None:
    stream = StringIO()
    setup_logging(stream=stream, environ={"R2MORPH_LOG_FORMAT": "json"})

    with logging_context(correlation_id="workflow-9", operation="workflow.run"):
        result = run_process([Path(sys.executable), "-c", "print('secret-argument')"], check=True)

    event = _json_events(stream)[0]
    expect_all(
        result.stdout_text.strip() == "secret-argument",
        event["event_name"] == "process.execute.completed",
        event["operation"] == "process.execute",
        event["correlation_id"] == "workflow-9",
        "secret-argument" not in json.dumps(event),
    )
