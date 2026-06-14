"""Pure filtering helpers for the TUI."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class FunctionFilter:
    """
    Filter and search functions in the TUI.

    Provides search by name pattern and filtering by size/address.
    """

    _pattern: str = ""
    _min_size: int = 0
    _max_size: int = 0
    _address_range: tuple[int, int] | None = None

    def set_pattern(self, pattern: str) -> None:
        """Set filter pattern for function names."""
        self._pattern = pattern.lower()

    def set_size_range(self, min_size: int = 0, max_size: int = 0) -> None:
        """Set size range filter. 0 means no limit."""
        self._min_size = min_size
        self._max_size = max_size

    def set_address_range(self, start: int, end: int) -> None:
        """Set address range filter."""
        self._address_range = (start, end)

    def matches(self, func: object) -> bool:
        """Check if function matches current filters."""
        name = getattr(func, "name", "")
        size = getattr(func, "size", 0)
        address = getattr(func, "address", 0)

        if self._pattern:
            if self._pattern not in name.lower():
                if not re.search(self._pattern, name, re.IGNORECASE):
                    return False

        if self._min_size > 0 and size < self._min_size:
            return False

        if self._max_size > 0 and size > self._max_size:
            return False

        if self._address_range:
            start, end = self._address_range
            if not (start <= address <= end):
                return False

        return True

    def filter_functions(self, functions: list[object]) -> list[object]:
        """Filter list of functions."""
        return [f for f in functions if self.matches(f)]

    def clear(self) -> None:
        """Clear all filters."""
        self._pattern = ""
        self._min_size = 0
        self._max_size = 0
        self._address_range = None
