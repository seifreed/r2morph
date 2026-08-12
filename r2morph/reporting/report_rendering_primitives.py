"""Shared primitives for report rendering helpers."""

from __future__ import annotations

from functools import cache
from typing import Any

from rich.console import Console
from rich.table import Table


@cache
def _get_console() -> Console:
    return Console()


class _LazyConsole:
    """Thin proxy so ``CONSOLE.print(...)`` keeps working."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_get_console(), name)


CONSOLE = _LazyConsole()


def create_table(title: str, columns: list[tuple[str, str]]) -> Table:
    """Create a styled table with columns."""
    table = Table(title=title)
    for name, style in columns:
        table.add_column(name, style=style)
    return table
