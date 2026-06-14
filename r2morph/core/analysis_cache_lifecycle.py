"""Background cleanup lifecycle helpers for analysis cache."""

from __future__ import annotations

import logging
import threading
from typing import Any


def start_cleanup_thread(cache: Any, logger: logging.Logger) -> None:
    """Start the background cleanup thread for an analysis cache instance."""

    def _cleanup_loop() -> None:
        while not cache._cleanup_stop_event.is_set():
            try:
                cache.cleanup_expired()
                cache.cleanup_low_access()
                cache._enforce_size_limit()
            except Exception as exc:
                logger.error(f"Error in cache cleanup: {exc}")

            cache._cleanup_stop_event.wait(cache.cleanup_interval_seconds)

    cache._cleanup_thread = threading.Thread(
        target=_cleanup_loop,
        name="r2morph-cache-cleanup",
        daemon=True,
    )
    cache._cleanup_thread.start()
    logger.debug("Started background cache cleanup thread")


def stop_cleanup_thread(cache: Any, logger: logging.Logger) -> None:
    """Stop the background cleanup thread for an analysis cache instance."""
    if cache._cleanup_thread and cache._cleanup_thread.is_alive():
        cache._cleanup_stop_event.set()
        cache._cleanup_thread.join(timeout=5.0)
        logger.debug("Stopped background cache cleanup thread")
