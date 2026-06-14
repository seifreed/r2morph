"""Pure value-analysis helpers for type inference."""

from __future__ import annotations

from typing import Any


def get_value_range(type_info: Any) -> tuple[int, int] | None:
    """Return the numeric value range for an integer type."""
    if not type_info.is_integer():
        return None

    size = type_info.size
    if size == 1:
        return (0, 255)
    if size == 2:
        return (0, 65535)
    if size == 4:
        return (0, 2**32 - 1)
    if size == 8:
        return (0, 2**64 - 1)
    return None


def is_safe_to_mutate(type_info: Any, mutation_type: str) -> tuple[bool, str]:
    """Check whether a mutation is safe for a value type."""
    if mutation_type == "register_substitution" and type_info.is_pointer():
        return (False, "Register holds pointer - unsafe to substitute")

    if mutation_type == "instruction_expansion" and type_info.is_pointer():
        return (False, "Pointer arithmetic - expansion may break semantics")

    return (True, "Safe to mutate")


__all__ = ["get_value_range", "is_safe_to_mutate"]
