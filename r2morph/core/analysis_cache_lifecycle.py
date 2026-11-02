"""Background cleanup lifecycle helpers for analysis cache."""

from __future__ import annotations

import logging
import threading
from typing import Any

_CLEANUP_THREAD_JOIN_TIMEOUT_SECONDS = 5.0


def _should_log_failure(failure_count: int) -> bool:
    """Log repeated cleanup failures at powers of two to bound noise."""
    return failure_count > 0 and failure_count & (failure_count - 1) == 0


def start_cleanup_thread(cache: Any, logger: logging.Logger) -> None:
    """Start the background cleanup thread for an analysis cache instance."""

    def _cleanup_loop() -> None:
        failure_count = 0
        while not cache._cleanup_stop_event.is_set():
            try:
                cache.cleanup_expired()
                cache.cleanup_low_access()
                cache._enforce_size_limit()
            except Exception as exc:
                failure_count += 1
                if _should_log_failure(failure_count):
                    logger.exception(
                        "Background cache cleanup failed: %s",
                        exc,
                        extra={
                            "event_name": "cache.cleanup.failed",
                            "operation": "cache.cleanup",
                            "outcome": "failure",
                            "error_code": "cache_cleanup_failed",
                        },
                    )
            else:
                if failure_count:
                    logger.info(
                        "Background cache cleanup recovered after %d failures",
                        failure_count,
                        extra={
                            "event_name": "cache.cleanup.recovered",
                            "operation": "cache.cleanup",
                            "outcome": "recovered",
                        },
                    )
                failure_count = 0

            cache._cleanup_stop_event.wait(cache.cleanup_interval_seconds)

    cache._cleanup_thread = threading.Thread(
        target=_cleanup_loop,
        name="r2morph-cache-cleanup",
        daemon=True,
    )
    cache._cleanup_thread.start()
    logger.info(
        "Started background cache cleanup",
        extra={"event_name": "cache.cleanup.started", "operation": "cache.cleanup", "outcome": "started"},
    )


def stop_cleanup_thread(cache: Any, logger: logging.Logger) -> None:
    """Stop the background cleanup thread for an analysis cache instance."""
    if cache._cleanup_thread and cache._cleanup_thread.is_alive():
        cache._cleanup_stop_event.set()
        cache._cleanup_thread.join(timeout=_CLEANUP_THREAD_JOIN_TIMEOUT_SECONDS)
        if cache._cleanup_thread.is_alive():
            logger.warning(
                "Background cache cleanup did not stop before timeout",
                extra={
                    "event_name": "cache.cleanup.stop_timeout",
                    "operation": "cache.cleanup",
                    "outcome": "timeout",
                },
            )
            return
        logger.info(
            "Stopped background cache cleanup",
            extra={"event_name": "cache.cleanup.stopped", "operation": "cache.cleanup", "outcome": "success"},
        )
