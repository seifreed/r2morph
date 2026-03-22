"""Shared utilities for the relocations package."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def get_endianness(binary: Any) -> str:
    """Detect binary endianness from architecture info.

    Args:
        binary: Binary instance with get_arch_info() method

    Returns:
        "little" or "big"
    """
    try:
        info = binary.get_arch_info()
        endian = info.get("endian", "little").lower()
        if endian in ("big", "be"):
            return "big"
    except Exception:
        pass
    return "little"
