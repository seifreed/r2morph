"""Regression test: setup_logging must not leak file handlers.

Bug: setup_logging() did ``logger.handlers.clear()``, which only drops
handler references -- it never calls ``handler.close()``. A previously
added ``logging.FileHandler`` therefore kept its underlying file open
until garbage collection finalized it, raising
``Exception ignored while finalizing file ... mode='ab'``. Under the
mandated ``pytest -W error`` that PytestUnraisableExceptionWarning is
fatal and gets attributed to whatever unrelated test happens to trigger
the GC -- flaky failures with shifting victims across the suite. It also
accumulated duplicate handlers (and duplicate log lines).

No mocks (CLAUDE.md s.4): real ``logging`` objects, real temp files.
Fails before the fix (stream stays open), passes after.
"""

from __future__ import annotations

import logging
from pathlib import Path

from r2morph.utils.logging import setup_logging


def test_repeated_setup_closes_previous_file_handler(tmp_path: Path) -> None:
    log_a = tmp_path / "a.log"
    log_b = tmp_path / "b.log"

    setup_logging(level="INFO", log_file=str(log_a))
    logger = logging.getLogger("r2morph")
    first_file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(first_file_handlers) == 1
    first = first_file_handlers[0]
    # Capture the stream object itself: FileHandler.close() sets
    # .stream = None, so we must check the original file object.
    first_stream = first.stream
    assert first_stream is not None and not first_stream.closed

    # Reconfiguring must close the old FileHandler's file, not orphan it.
    setup_logging(level="INFO", log_file=str(log_b))

    assert first_stream.closed, "previous FileHandler leaked an open file"

    # No handler accumulation: exactly one console + one file handler.
    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 1
    assert len(logger.handlers) == 2


def test_repeated_setup_without_file_does_not_accumulate(tmp_path: Path) -> None:
    setup_logging(level="INFO", log_file=str(tmp_path / "c.log"))
    setup_logging(level="DEBUG")  # console only
    logger = logging.getLogger("r2morph")

    assert len(logger.handlers) == 1
    assert not any(isinstance(h, logging.FileHandler) for h in logger.handlers)
