"""Safe, structured logging configuration for r2morph."""

from __future__ import annotations

import atexit
import hashlib
import json
import logging
import os
import re
import sys
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from itertools import islice
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TextIO

_SERVICE_NAME = "r2morph"
_DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_BACKUP_COUNT = 5
_MAX_COLLECTION_ITEMS = 20
_MAX_MESSAGE_CHARACTERS = 4096
_VALID_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_VALID_FORMATS = frozenset({"console", "json"})
_SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "access_token",
        "authorization",
        "cookie",
        "password",
        "passwd",
        "private_key",
        "refresh_token",
        "secret",
        "session",
        "session_id",
        "token",
    }
)
_EVENT_FIELDS = (
    "operation",
    "event_name",
    "request_id",
    "correlation_id",
    "trace_id",
    "span_id",
    "duration_ms",
    "status",
    "outcome",
    "error_type",
    "error_code",
    "failed_pass_count",
    "mutation_count",
    "pass_index",
    "pass_name",
    "pass_total",
    "rolled_back_pass_count",
)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|access_token|refresh_token|api[-_]?key|secret|authorization|cookie|session)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
    re.DOTALL,
)
_POSIX_PATH = re.compile(r"(?<![\w:/])/(?:[^/\s]+/)*[^/\s,;:)\]}]+")
_WINDOWS_PATH = re.compile(r"(?i)(?<!\w)[a-z]:\\(?:[^\\\s]+\\)*[^\\\s,;:)\]}]+")

_correlation_id: ContextVar[str | None] = ContextVar("r2morph_correlation_id", default=None)
_operation: ContextVar[str | None] = ContextVar("r2morph_operation", default=None)


def _validated_level(value: str) -> str:
    level = value.upper()
    if level not in _VALID_LEVELS:
        choices = ", ".join(sorted(_VALID_LEVELS))
        raise ValueError(f"Invalid log level {value!r}; expected one of: {choices}")
    return level


def _validated_format(value: str) -> str:
    format_name = value.lower()
    if format_name not in _VALID_FORMATS:
        choices = ", ".join(sorted(_VALID_FORMATS))
        raise ValueError(f"Invalid log format {value!r}; expected one of: {choices}")
    return format_name


def _positive_integer(value: str, name: str, *, allow_zero: bool = False) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    minimum = 0 if allow_zero else 1
    if parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return parsed


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    """Validated logging settings resolved at the process boundary."""

    level: str = "INFO"
    format_name: str = "console"
    environment: str = "development"
    log_file: Path | None = None
    max_bytes: int = _DEFAULT_MAX_BYTES
    backup_count: int = _DEFAULT_BACKUP_COUNT

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> LoggingConfig:
        values = os.environ if environ is None else environ
        environment = values.get("R2MORPH_ENVIRONMENT", "development").strip() or "development"
        requested_format = values.get("R2MORPH_LOG_FORMAT")
        format_name = requested_format or ("json" if environment.lower() == "production" else "console")
        log_file_value = values.get("R2MORPH_LOG_FILE")
        return cls(
            level=_validated_level(values.get("R2MORPH_LOG_LEVEL", "INFO")),
            format_name=_validated_format(format_name),
            environment=environment,
            log_file=Path(log_file_value).expanduser() if log_file_value else None,
            max_bytes=_positive_integer(values.get("R2MORPH_LOG_MAX_BYTES", str(_DEFAULT_MAX_BYTES)), "max bytes"),
            backup_count=_positive_integer(
                values.get("R2MORPH_LOG_BACKUP_COUNT", str(_DEFAULT_BACKUP_COUNT)),
                "backup count",
                allow_zero=True,
            ),
        )


def _escaped_control_character(match: re.Match[str]) -> str:
    character = match.group(0)
    common = {"\n": r"\n", "\r": r"\r", "\t": r"\t"}
    return common.get(character, f"\\x{ord(character):02x}")


def _path_placeholder(match: re.Match[str]) -> str:
    value = match.group(0).rstrip(".")
    normalized = value.replace("\\", "/")
    return f"<path:{normalized.rsplit('/', 1)[-1]}>"


def sanitize_log_text(value: str) -> str:
    """Redact secrets, host paths, and log-injection control characters."""
    sanitized = _PRIVATE_KEY.sub("<redacted-private-key>", value)
    sanitized = _BEARER_TOKEN.sub("Bearer <redacted>", sanitized)
    sanitized = _SECRET_ASSIGNMENT.sub(r"\1\2<redacted>", sanitized)
    sanitized = _WINDOWS_PATH.sub(_path_placeholder, sanitized)
    sanitized = _POSIX_PATH.sub(_path_placeholder, sanitized)
    sanitized = _CONTROL_CHARACTERS.sub(_escaped_control_character, sanitized)
    if len(sanitized) <= _MAX_MESSAGE_CHARACTERS:
        return sanitized
    omitted = len(sanitized) - _MAX_MESSAGE_CHARACTERS
    return f"{sanitized[:_MAX_MESSAGE_CHARACTERS]}<truncated:{omitted}>"


def _safe_value(value: object, *, key: str | None = None) -> object:
    if key is not None and key.lower() in _SENSITIVE_KEYS:
        result: object = "<redacted>"
    elif isinstance(value, Path):
        result = f"<path:{value.name}>"
    elif isinstance(value, bytes):
        digest = hashlib.sha256(value).hexdigest()[:12]
        result = {"size": len(value), "sha256_prefix": digest}
    elif isinstance(value, str):
        result = sanitize_log_text(value)
    elif isinstance(value, Mapping):
        item_count = len(value)
        items = list(islice(value.items(), _MAX_COLLECTION_ITEMS))
        safe_mapping = {str(item_key): _safe_value(item_value, key=str(item_key)) for item_key, item_value in items}
        if item_count > _MAX_COLLECTION_ITEMS:
            safe_mapping["_truncated_items"] = item_count - _MAX_COLLECTION_ITEMS
        result = safe_mapping
    elif isinstance(value, (list, tuple, set, frozenset)):
        item_count = len(value)
        items = list(islice(value, _MAX_COLLECTION_ITEMS))
        safe_items = [_safe_value(item) for item in items]
        if item_count > _MAX_COLLECTION_ITEMS:
            safe_items.append(f"<truncated:{item_count - _MAX_COLLECTION_ITEMS}>")
        result = safe_items
    elif value is None or isinstance(value, (bool, int, float)):
        result = value
    else:
        result = sanitize_log_text(str(value))
    return result


class ContextFilter(logging.Filter):
    """Attach operation context without mutable process-global state."""

    def filter(self, record: logging.LogRecord) -> bool:
        correlation_id = _correlation_id.get()
        operation = _operation.get()
        if correlation_id is not None and not hasattr(record, "correlation_id"):
            record.correlation_id = correlation_id
        if operation is not None and not hasattr(record, "operation"):
            record.operation = operation
        return True


class ProcessOwnerFilter(logging.Filter):
    """Keep inherited handlers in their configuring process."""

    def __init__(self, owner_pid: int) -> None:
        super().__init__()
        self.owner_pid = owner_pid

    def filter(self, record: logging.LogRecord) -> bool:
        return record.process == self.owner_pid


class SafeTextFormatter(logging.Formatter):
    """Human-readable formatter with the same safety policy as JSON logs."""

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        correlation_id = getattr(record, "correlation_id", None)
        operation = getattr(record, "operation", None)
        if correlation_id is not None:
            formatted = f"{formatted} correlation_id={correlation_id}"
        if operation is not None:
            formatted = f"{formatted} operation={operation}"
        return sanitize_log_text(formatted)


class JsonFormatter(logging.Formatter):
    """Emit one normalized JSON object per record."""

    def __init__(self, environment: str) -> None:
        super().__init__()
        self.environment = sanitize_log_text(environment)

    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "message": sanitize_log_text(record.getMessage()),
            "service": _SERVICE_NAME,
            "component": record.name,
            "environment": self.environment,
            "process_id": record.process,
            "thread_name": record.threadName,
        }
        for field in _EVENT_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                event[field] = _safe_value(value, key=field)
        if record.exc_info:
            exception = record.exc_info[1]
            event["error_type"] = type(exception).__name__ if exception is not None else "UnknownError"
            event["stack_trace"] = sanitize_log_text(self.formatException(record.exc_info))
        return json.dumps(event, ensure_ascii=False, separators=(",", ":"))


def _formatter(config: LoggingConfig) -> logging.Formatter:
    if config.format_name == "json":
        return JsonFormatter(config.environment)
    return SafeTextFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def _close_handlers(logger: logging.Logger) -> None:
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()


def _configured_stream(stream: TextIO | None) -> TextIO:
    if stream is not None:
        return stream
    stable_stderr: TextIO | None = sys.__stderr__
    if stable_stderr is None or stable_stderr.closed:
        stable_stderr = sys.stderr
    return stable_stderr


def _add_file_handler(logger: logging.Logger, config: LoggingConfig, formatter: logging.Formatter) -> None:
    if config.log_file is None:
        return
    try:
        handler = RotatingFileHandler(
            config.log_file,
            maxBytes=config.max_bytes,
            backupCount=config.backup_count,
            encoding="utf-8",
        )
    except OSError as exc:
        logger.warning(
            "File logging unavailable: %s",
            exc,
            extra={"event_name": "logging.destination_unavailable", "outcome": "degraded"},
        )
        return
    handler.setLevel(config.level)
    handler.setFormatter(formatter)
    handler.addFilter(ContextFilter())
    handler.addFilter(ProcessOwnerFilter(os.getpid()))
    logger.addHandler(handler)


def _apply_legacy_overrides(
    config: LoggingConfig,
    level: str | None,
    log_file: str | Path | None,
) -> LoggingConfig:
    if level is not None:
        config = replace(config, level=_validated_level(level))
    if log_file is not None:
        config = replace(config, log_file=Path(log_file).expanduser())
    return config


def setup_logging(
    level: str | None = None,
    log_file: str | Path | None = None,
    *,
    config: LoggingConfig | None = None,
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
) -> logging.Logger:
    """Configure the package logger from explicit values and environment."""
    resolved_config = config or LoggingConfig.from_environment(environ)
    resolved_config = _apply_legacy_overrides(resolved_config, level, log_file)
    logger = logging.getLogger(_SERVICE_NAME)
    _close_handlers(logger)
    logger.setLevel(resolved_config.level)
    logger.propagate = False
    formatter = _formatter(resolved_config)
    console_handler = logging.StreamHandler(_configured_stream(stream))
    console_handler.setLevel(resolved_config.level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(ContextFilter())
    console_handler.addFilter(ProcessOwnerFilter(os.getpid()))
    logger.addHandler(console_handler)
    _add_file_handler(logger, resolved_config, formatter)
    logger.debug(
        "Logging configured",
        extra={"event_name": "logging.configured", "operation": "logging.configure", "outcome": "success"},
    )
    return logger


def shutdown_logging() -> None:
    """Flush and close r2morph handlers during controlled shutdown."""
    logger = logging.getLogger(_SERVICE_NAME)
    _close_handlers(logger)
    logger.setLevel(logging.NOTSET)
    logger.propagate = True


def log_exception_once(
    logger: logging.Logger,
    message: str,
    error: Exception,
    *,
    extra: Mapping[str, object],
) -> None:
    """Emit one traceback for an exception while retaining parent outcomes."""
    fields = {**extra, "error_type": type(error).__name__}
    formatted_message = f"{message}: %s"
    if getattr(error, "_r2morph_traceback_logged", False):
        logger.error(formatted_message, error, extra=fields)
        return
    logger.error(
        formatted_message,
        error,
        exc_info=(type(error), error, error.__traceback__),
        extra=fields,
    )
    try:
        error.__dict__["_r2morph_traceback_logged"] = True
    except (AttributeError, TypeError):
        return


@contextmanager
def logging_context(*, correlation_id: str | None = None, operation: str | None = None) -> Iterator[None]:
    """Bind correlation fields for nested sync and async work."""
    tokens: list[tuple[ContextVar[str | None], Token[str | None]]] = []
    if correlation_id is not None:
        tokens.append((_correlation_id, _correlation_id.set(correlation_id)))
    if operation is not None:
        tokens.append((_operation, _operation.set(operation)))
    try:
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


@contextmanager
def observed_operation(
    logger: logging.Logger,
    operation: str,
    *,
    event_name: str,
    correlation_id: str | None = None,
) -> Iterator[str]:
    """Record one operation outcome and duration while preserving failures."""
    operation_id = correlation_id or _correlation_id.get() or uuid.uuid4().hex
    start = time.perf_counter()
    with logging_context(correlation_id=operation_id, operation=operation):
        logger.debug(
            "Operation started",
            extra={"event_name": f"{event_name}.started", "outcome": "started"},
        )
        try:
            yield operation_id
        except Exception as exc:
            log_exception_once(
                logger,
                "Operation failed",
                exc,
                extra={
                    "event_name": f"{event_name}.failed",
                    "duration_ms": round((time.perf_counter() - start) * 1000, 3),
                    "outcome": "failure",
                },
            )
            raise
        logger.info(
            "Operation completed",
            extra={
                "event_name": f"{event_name}.completed",
                "duration_ms": round((time.perf_counter() - start) * 1000, 3),
                "outcome": "success",
            },
        )


atexit.register(shutdown_logging)
