"""Cache command orchestration for the CLI."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from r2morph.cli_cache_output import (
    build_cache_cleared_message,
    build_cache_statistics_lines,
    build_cache_usage_hint,
)
from r2morph.core.analysis_cache import AnalysisCache


def handle_cache_command(
    *,
    clear: bool,
    stats: bool,
    path: Path | None,
    console: Console,
    cache_cls: type[AnalysisCache] = AnalysisCache,
) -> None:
    cache_dir = path if path else None
    cache_instance = cache_cls(cache_dir=cache_dir)

    if stats:
        statistics = cache_instance.get_stats()
        for line in build_cache_statistics_lines(statistics):
            if line == "Cache Statistics:":
                console.print(f"[cyan]{line}[/cyan]")
            else:
                console.print(line)
        return

    if clear:
        cleared = cache_instance.clear()
        console.print(f"[green]{build_cache_cleared_message(cleared)}[/green]")
        return

    console.print(f"[yellow]{build_cache_usage_hint()}[/yellow]")
    raise SystemExit(1)
