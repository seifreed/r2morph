"""Shared utilities for the relocations package."""

import logging
from typing import Any, Literal

logger = logging.getLogger(__name__)

ByteOrder = Literal["little", "big"]


def get_endianness(binary: Any) -> ByteOrder:
    """Detect binary endianness from architecture info.

    Args:
        binary: Binary instance with get_arch_info() method

    Returns:
        "little" or "big"
    """
    try:
        info = binary.get_arch_info()
    except (AttributeError, TypeError) as exc:
        logger.warning("Cannot read arch info from binary (%s); defaulting to little-endian", exc)
        return "little"

    endian = info.get("endian", "little") if isinstance(info, dict) else "little"
    if isinstance(endian, str) and endian.lower() in ("big", "be"):
        return "big"
    return "little"
