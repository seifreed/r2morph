"""Lifecycle helpers for enhanced binary analysis."""

from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def ensure_dependencies() -> bool:
    """Check and import enhanced analysis dependencies."""
    return (
        importlib.util.find_spec("r2morph.detection") is not None
        and importlib.util.find_spec("r2morph.devirtualization") is not None
    )


def load_binary(binary_path: Path) -> Any:
    """Load and analyze the binary."""
    from r2morph import Binary

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
    except Exception as exc:  # pragma: no cover - defensive cleanup path
        logger.debug(f"Error cleaning up binary: {exc}")

