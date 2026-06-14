"""Progress indicator used by the TUI."""

from __future__ import annotations

from typing import Any

Console: Any
try:
    from rich.console import Console
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class _FallbackConsole:
        def print(self, *args: Any, **kwargs: Any) -> None:
            print(*args)

    Console = _FallbackConsole
    Progress = SpinnerColumn = BarColumn = TextColumn = TimeElapsedColumn = None


class TUIProgressIndicator:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._progress: Progress | None = None
        self._task_id: Any = None

    def start(self, total: int, description: str = "Processing") -> None:
        if RICH_AVAILABLE:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=self.console,
            )
            self._progress.start()
            self._task_id = self._progress.add_task(description, total=total)

    def update(self, advance: int = 1, message: str | None = None) -> None:
        if self._progress and self._task_id is not None:
            self._progress.update(self._task_id, advance=advance, description=message)

    def complete(self, message: str = "Complete") -> None:
        if self._progress and self._task_id is not None:
            self._progress.update(self._task_id, description=message)
            self._progress.stop()

    def stop(self) -> None:
        if self._progress:
            self._progress.stop()
