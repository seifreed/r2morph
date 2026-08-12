"""Lifecycle helpers for enhanced binary analysis."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


def load_binary(binary_path: Path) -> Any:
    """Load and analyze the binary."""
    binary = Binary(str(binary_path))
    binary.__enter__()
    binary.analyze()
    return binary


def cleanup_binary(binary: Any) -> None:
    """Clean up a loaded binary context."""
    if binary is None:
        return

    try:
        binary.__exit__(None, None, None)
    except Exception as exc:
        logger.debug(f"Error cleaning up binary: {exc}")
