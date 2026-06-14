"""Shared address parsing helpers for validation flows."""

from __future__ import annotations


def parse_address(value: int | str | None) -> int:
    """Parse an address that may be an int or hex string like '0x401010'."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.startswith("0x"):
        return int(value, 16)
    return int(value)
