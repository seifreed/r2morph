"""
Interactive Terminal User Interface (TUI) for r2morph.

Provides an interactive interface for:
- Function selection with search/filter
- Pass selection with descriptions
- Before/after disassembly preview with diff view
- Mutation confirmation workflow
- Progress indication

Uses the rich library for terminal rendering with fallback to basic text mode.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from r2morph import tui_models as _tui_models
from r2morph import tui_rendering as _tui_rendering
from r2morph.tui_diff_view import DiffView as _DiffView
from r2morph.tui_filters import FunctionFilter

TUIAction = _tui_models.TUIAction
TUIMutation = _tui_models.TUIMutation
TUIFunction = _tui_models.TUIFunction
TUIPass = _tui_models.TUIPass
TUIResult = _tui_models.TUIResult
TUIProgress = _tui_models.TUIProgress
DiffView = _DiffView

Console = _tui_rendering.Console
Confirm = _tui_rendering.Confirm
Layout = _tui_rendering.Layout
Panel = _tui_rendering.Panel
Progress = _tui_rendering.Progress
Prompt = _tui_rendering.Prompt
RICH_AVAILABLE = _tui_rendering.RICH_AVAILABLE
SpinnerColumn = _tui_rendering.SpinnerColumn
TUIConfigScreen = _tui_rendering.TUIConfigScreen
TUIFunctionScreen = _tui_rendering.TUIFunctionScreen
TUIMainScreen = _tui_rendering.TUIMainScreen
TUIPassConfig = _tui_rendering.TUIPassConfig
TUIPassScreen = _tui_rendering.TUIPassScreen
TUIPreviewScreen = _tui_rendering.TUIPreviewScreen
TUIProgressIndicator = _tui_rendering.TUIProgressIndicator
Table = _tui_rendering.Table
Text = _tui_rendering.Text
TextColumn = _tui_rendering.TextColumn
TimeElapsedColumn = _tui_rendering.TimeElapsedColumn

logger = logging.getLogger(__name__)


class MutationTUI:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console() if RICH_AVAILABLE else Console()
        self.main_screen = TUIMainScreen(self.console)
        self.function_screen = TUIFunctionScreen(self.console)
        self.pass_screen = TUIPassScreen(self.console)
        self.preview_screen = TUIPreviewScreen(self.console)
        self.progress_indicator = TUIProgressIndicator(self.console)

    def run(
        self,
        functions: list[TUIFunction],
        passes: list[TUIPass],
        on_execute: Callable[[list[TUIFunction], list[TUIPass]], list[TUIMutation]],
    ) -> TUIResult | None:
        result = TUIResult(functions=functions, passes=passes)
        current_page = 0
        mutations: list[TUIMutation] = []
        state = "main"

        while True:
            try:
                if state == "main":
                    self.main_screen.render()
                    key = self._get_input()
                    if key.lower() == "f":
                        state = "functions"
                    elif key.lower() == "p":
                        state = "passes"
                    elif key.lower() == "v":
                        mutations = on_execute(result.functions, result.passes)
                        state = "preview"
                    elif key.lower() == "e":
                        if self._confirm():
                            result.confirmed = True
                            return result
                    elif key.lower() == "q":
                        return None

                elif state == "functions":
                    self.function_screen.render(result.functions)
                    key = self._get_input()
                    if key.lower() == "a":
                        for f in result.functions:
                            f.selected = True
                    elif key.lower() == "n":
                        for f in result.functions:
                            f.selected = False
                    elif key.lower() == "c":
                        state = "main"
                    elif key.isdigit():
                        idx = int(key)
                        if 0 <= idx < len(result.functions):
                            result.functions[idx].selected = not result.functions[idx].selected

                elif state == "passes":
                    self.pass_screen.render(result.passes)
                    key = self._get_input()
                    if key.lower() == "a":
                        for p in result.passes:
                            p.selected = True
                    elif key.lower() == "n":
                        for p in result.passes:
                            p.selected = False
                    elif key.lower() == "c":
                        state = "main"
                    elif key.isdigit():
                        idx = int(key)
                        if 0 <= idx < len(result.passes):
                            result.passes[idx].selected = not result.passes[idx].selected

                elif state == "preview":
                    self.preview_screen.render(mutations, page=current_page)
                    key = self._get_input()
                    if key.lower() == "n":
                        max_page = (len(mutations) + 9) // 10
                        current_page = min(current_page + 1, max_page - 1)
                    elif key.lower() == "p":
                        current_page = max(current_page - 1, 0)
                    elif key.lower() == "e":
                        if self._confirm():
                            result.confirmed = True
                            return result
                    elif key.lower() == "q":
                        state = "main"

            except KeyboardInterrupt:
                return None

        return None

    def _get_input(self) -> str:
        if RICH_AVAILABLE:
            return Prompt.ask(">", console=self.console)
        else:
            return input("> ").strip()

    def _confirm(self) -> bool:
        if RICH_AVAILABLE:
            return Confirm.ask("Execute mutations?", console=self.console, default=True)
        else:
            response = input("Execute mutations? [Y/n]: ").strip().lower()
            return response in ("", "y", "yes")

    def show_preview(self, mutations: list[TUIMutation]) -> None:
        page = 0
        while True:
            self.preview_screen.render(mutations, page=page)
            key = self._get_input()
            max_page = (len(mutations) + 9) // 10
            if key.lower() == "n" and page < max_page - 1:
                page += 1
            elif key.lower() == "p" and page > 0:
                page -= 1
            elif key.lower() == "q":
                break

    def select_functions(self, functions: list[TUIFunction]) -> list[TUIFunction]:
        selected = list(functions)
        while True:
            self.function_screen.render(selected)
            key = self._get_input()
            if key.lower() == "a":
                for f in selected:
                    f.selected = True
            elif key.lower() == "n":
                for f in selected:
                    f.selected = False
            elif key.lower() == "c":
                return [f for f in selected if f.selected]
            elif key.isdigit():
                idx = int(key)
                if 0 <= idx < len(selected):
                    selected[idx].selected = not selected[idx].selected

    def select_passes(self, passes: list[TUIPass]) -> list[TUIPass]:
        selected = list(passes)
        while True:
            self.pass_screen.render(selected)
            key = self._get_input()
            if key.lower() == "a":
                for p in selected:
                    p.selected = True
            elif key.lower() == "n":
                for p in selected:
                    p.selected = False
            elif key.lower() == "c":
                return [p for p in selected if p.selected]
            elif key.isdigit():
                idx = int(key)
                if 0 <= idx < len(selected):
                    selected[idx].selected = not selected[idx].selected

    def confirm_mutations(self, mutation_count: int) -> bool:
        if RICH_AVAILABLE:
            self.console.print(f"\n[bold yellow]{mutation_count}[/bold yellow] mutations will be applied.")
            return Confirm.ask("Proceed?", console=self.console, default=True)
        else:
            print(f"\n{mutation_count} mutations will be applied.")
            response = input("Proceed? [Y/n]: ").strip().lower()
            return response in ("", "y", "yes")

    def show_progress(self, total: int, description: str = "Processing") -> TUIProgressIndicator:
        indicator = TUIProgressIndicator(self.console)
        if RICH_AVAILABLE:
            indicator.start(total, description)
        return indicator


def create_default_passes() -> list[TUIPass]:
    return [
        TUIPass(name="nop", description="Insert benign NOP instructions", is_stable=True),
        TUIPass(
            name="substitute",
            description="Replace instructions with equivalents",
            is_stable=True,
        ),
        TUIPass(
            name="register",
            description="Substitute registers safely",
            is_stable=True,
        ),
        TUIPass(name="block", description="Reorder basic blocks", is_stable=False),
        TUIPass(
            name="dead-code",
            description="Inject dead code sequences",
            is_stable=False,
        ),
        TUIPass(
            name="opaque",
            description="Insert opaque predicates",
            is_stable=False,
        ),
        TUIPass(
            name="expand",
            description="Expand instructions to longer forms",
            is_stable=False,
        ),
        TUIPass(name="cff", description="Flatten control flow", is_stable=False),
    ]


def run_interactive_mode(
    functions: list[Any],
    passes: list[Any] | None = None,
    on_execute: Callable | None = None,
) -> dict[str, Any] | None:
    tui = MutationTUI()
    tui_functions = [
        TUIFunction(
            address=f.get("address", 0),
            name=f.get("name", "unknown"),
            size=f.get("size", 0),
        )
        for f in functions
    ]
    tui_passes = passes or [
        TUIPass(
            name=getattr(p, "name", ""),
            description=getattr(p, "description", ""),
            is_stable=getattr(p, "is_stable", False),
        )
        for p in create_default_passes()
    ]
    if not on_execute:

        def default_execute(funcs: list[TUIFunction], passes: list[TUIPass]) -> list[TUIMutation]:
            return []

        on_execute = default_execute

    result = tui.run(tui_functions, tui_passes, on_execute)

    if result is None:
        return None

    return {
        "functions": [
            {"address": f.address, "name": f.name, "selected": f.selected} for f in result.functions if f.selected
        ],
        "passes": [{"name": p.name, "selected": p.selected} for p in result.passes if p.selected],
        "confirmed": result.confirmed,
    }
class FunctionSearchScreen:
    """
    Interactive function search and filter screen.

    Provides:
    - Pattern search for function names
    - Size filter
    - Address range filter
    """

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._filter = FunctionFilter()
        self._search_mode = False
        self._search_query = ""

    def handle_input(self, key: str) -> None:
        """Handle keyboard input for search mode."""
        if self._search_mode:
            if key == "escape":
                self._search_mode = False
                self._search_query = ""
            elif key == "enter":
                self._filter.set_pattern(self._search_query)
                self._search_mode = False
            elif key == "backspace":
                self._search_query = self._search_query[:-1]
            else:
                self._search_query += key

    def enter_search_mode(self) -> None:
        """Enter search mode."""
        self._search_mode = True
        self._search_query = ""

    def render(self, functions: list[TUIFunction], filtered: list[TUIFunction]) -> None:
        """Render function list with search UI."""
        if RICH_AVAILABLE:
            self._render_rich(functions, filtered)
        else:
            self._render_basic(functions, filtered)

    def _render_rich(self, functions: list[TUIFunction], filtered: list[TUIFunction]) -> None:
        """Render with rich formatting."""
        if self._search_mode:
            self.console.print(f"\n[bold cyan]Search:[/bold cyan] {self._search_query}_")
        else:
            self.console.print("\n[bold]Function Selection[/bold]")
            if self._filter._pattern:
                self.console.print(f"[dim]Filter: '{self._filter._pattern}' ({len(filtered)} matches)[/dim]")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Sel", style="cyan", width=4)
        table.add_column("#", style="dim", width=4)
        table.add_column("Address", style="green")
        table.add_column("Name", style="yellow")
        table.add_column("Size", style="magenta")

        for i, func in enumerate(filtered[:20]):  # Limit to 20 for readability
            sel = "[X]" if func.selected else "[ ]"
            table.add_row(
                sel,
                str(i),
                f"0x{func.address:x}",
                func.name,
                str(func.size),
            )

        self.console.print(table)

        if len(filtered) > 20:
            self.console.print(f"[dim]... and {len(filtered) - 20} more[/dim]")

        if self._search_mode:
            self.console.print("\n[dim]Type to search | ESC to cancel | ENTER to confirm[/dim]")
        else:
            self.console.print("\n[dim]/: search | f: filter | c: confirm | q: quit[/dim]")

    def _render_basic(self, functions: list[TUIFunction], filtered: list[TUIFunction]) -> None:
        """Render with basic formatting."""
        if self._search_mode:
            print(f"\nSearch: {self._search_query}_")
        else:
            print("\nFunction Selection")
            if self._filter._pattern:
                print(f"Filter: '{self._filter._pattern}' ({len(filtered)} matches)")

        for i, func in enumerate(filtered[:20]):
            sel = "[X]" if func.selected else "[ ]"
            print(f"  {sel} {i}: 0x{func.address:x} {func.name} ({func.size})")

        if len(filtered) > 20:
            print(f"  ... and {len(filtered) - 20} more")

        if self._search_mode:
            print("\nType to search | ESC to cancel | ENTER to confirm")
        else:
            print("\n/: search | f: filter | c: confirm | q: quit")
