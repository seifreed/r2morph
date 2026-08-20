from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.cli_cache_command import handle_cache_command
from r2morph.core.analysis_cache_models import CacheStats
from tests.utils.assertions import expect


class _FakeCache:
    def __init__(self, *, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir
        self.cleared = False

    def get_stats(self) -> CacheStats:
        return CacheStats(hits=3, misses=1, entry_count=2, total_size_bytes=1024)

    def clear(self) -> int:
        self.cleared = True
        return 7


class _FakeConsole:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, text: str) -> None:
        self.lines.append(text)


def test_cli_cache_command_contract_stats_clear_and_usage_hint() -> None:
    console = _FakeConsole()

    handle_cache_command(clear=False, stats=True, path=Path("test-data/cache"), console=console, cache_cls=_FakeCache)
    expect(any("Cache Statistics:" in line for line in console.lines))
    expect(any("Hits: 3" in line for line in console.lines))

    console = _FakeConsole()
    handle_cache_command(clear=True, stats=False, path=None, console=console, cache_cls=_FakeCache)
    expect(console.lines == ["[green]Cleared 7 cache entries[/green]"])

    console = _FakeConsole()
    with pytest.raises(SystemExit) as excinfo:
        handle_cache_command(clear=False, stats=False, path=None, console=console, cache_cls=_FakeCache)
    expect(excinfo.value.code == 1)
    expect(console.lines == ["[yellow]Specify --clear or --stats[/yellow]"])
