"""Binary r2pipe lifecycle helpers."""

from __future__ import annotations

import logging
import time
from typing import Any

from r2morph.core.constants import BATCH_MUTATION_CHECKPOINT

logger = logging.getLogger(__name__)

_R2PIPE_OPEN_ATTEMPTS = 3
_R2PIPE_OPEN_RETRY_BACKOFF_SECONDS = 0.25


def _discard_failed_r2(binary: Any) -> None:
    r2 = binary.r2
    binary.r2 = None
    if r2 is not None and hasattr(r2, "quit"):
        try:
            r2.quit()
        except (BrokenPipeError, OSError) as exc:
            logger.debug("Ignoring teardown error on broken r2 pipe: %s", exc)


def _spawn_r2(binary: Any) -> Any:
    return binary._spawn_r2()


def _open_r2pipe_with_retry(binary: Any) -> None:
    last_error: Exception | None = None
    for attempt in range(1, _R2PIPE_OPEN_ATTEMPTS + 1):
        try:
            binary.r2 = _spawn_r2(binary)
            binary.info = binary.r2.cmdj("ij") or {}
            return
        except (BrokenPipeError, ConnectionError, OSError) as exc:
            last_error = exc
            logger.warning(
                "r2pipe spawn failed for %s (attempt %d/%d): %s",
                binary.path,
                attempt,
                _R2PIPE_OPEN_ATTEMPTS,
                exc,
            )
            _discard_failed_r2(binary)
            if attempt < _R2PIPE_OPEN_ATTEMPTS:
                time.sleep(_R2PIPE_OPEN_RETRY_BACKOFF_SECONDS * attempt)
    assert last_error is not None
    raise last_error


def open_binary(binary: Any) -> Any:
    try:
        logger.info(f"Opening binary: {binary.path}")
        if binary._injected_disassembler is not None:
            binary._injected_disassembler.open(binary.path, binary.flags)
            binary.r2 = binary._injected_disassembler
            binary.info = binary.r2.cmdj("ij") or {}
        else:
            _open_r2pipe_with_retry(binary)

        if binary._low_memory:
            logger.debug("Configuring r2 for low memory mode")
            binary.r2.cmd("e bin.cache=false")
            binary.r2.cmd("e io.cache=false")
            binary.r2.cmd("e bin.strings=false")

        logger.debug(f"Binary info: {binary.info.get('core', {}).get('format', 'unknown')}")

        if binary._reader:
            binary._reader.set_r2(binary.r2)
        if binary._writer:
            binary._writer.set_r2(binary.r2)

    except Exception as exc:
        _discard_failed_r2(binary)
        raise RuntimeError(f"Failed to open binary with r2pipe: {exc}") from exc
    return binary


def close_binary(binary: Any) -> None:
    if binary.r2:
        if hasattr(binary.r2, "quit"):
            binary.r2.quit()
        binary.r2 = None
        logger.info(f"Closed binary: {binary.path}")


def reload_binary(binary: Any) -> None:
    logger.debug("Reloading r2 connection to free memory")
    was_analyzed = binary._analyzed
    with binary._lock:
        close_binary(binary)
        binary._reader = None
        binary._writer = None
        open_binary(binary)
    if was_analyzed:
        analyze_binary(binary)
    else:
        binary._analyzed = False
        binary._functions_cache = None


def analyze_binary(binary: Any, level: str = "aaa") -> Any:
    if not binary.r2:
        raise RuntimeError("Binary not opened. Call open() first.")

    logger.info(f"Running analysis: {level}")

    if level in ["aaa", "aaaa"]:
        logger.warning("Analysis may take 2-5 minutes for large binaries. Please wait...")

    binary.r2.cmd(level)
    binary._analyzed = True

    try:
        binary._functions_cache = binary.r2.cmdj("aflj") or []
        logger.info(f"Analysis complete - cached {len(binary._functions_cache)} functions")
    except Exception as exc:
        logger.warning(f"Failed to cache functions: {exc}")
        binary._functions_cache = None

    return binary


def track_mutation_count(binary: Any, batch_size: int = BATCH_MUTATION_CHECKPOINT) -> None:
    if not binary._low_memory:
        return

    binary._mutation_counter += 1
    if binary._mutation_counter % batch_size == 0:
        logger.info(f"Batch checkpoint: {binary._mutation_counter} mutations applied. Reloading r2 to free memory...")
        reload_binary(binary)
