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
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph import tui_rendering as _tui_rendering

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


class TUIAction(str, Enum):
    SELECT_FUNCTIONS = "select_functions"
    SELECT_PASSES = "select_passes"
    PREVIEW_MUTATIONS = "preview_mutations"
    CONFIRM = "confirm"
    EXECUTE = "execute"
    CANCEL = "cancel"


@dataclass
class TUIMutation:
    address: int
    function: str | None
    pass_name: str
    original_bytes: bytes
    mutated_bytes: bytes
    description: str | None = None
    original_disasm: list[str] | None = None
    mutated_disasm: list[str] | None = None


@dataclass
class TUIFunction:
    address: int
    name: str
    size: int
    selected: bool = False


@dataclass
class TUIPass:
    name: str
    description: str
    is_stable: bool
    selected: bool = False
    configurable: bool = False
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class TUIResult:
    functions: list[TUIFunction]
    passes: list[TUIPass]
    confirmed: bool = False


@dataclass
class TUIProgress:
    total: int = 0
    current: int = 0
    message: str = ""
    status: str = "running"


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


class FunctionFilter:
    """
    Filter and search functions in the TUI.

    Provides search by name pattern and filtering by size/address.
    """

    def __init__(self) -> None:
        self._pattern: str = ""
        self._min_size: int = 0
        self._max_size: int = 0
        self._address_range: tuple[int, int] | None = None

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

    def matches(self, func: TUIFunction) -> bool:
        """Check if function matches current filters."""
        if self._pattern:
            if self._pattern not in func.name.lower():
                if not re.search(self._pattern, func.name, re.IGNORECASE):
                    return False

        if self._min_size > 0 and func.size < self._min_size:
            return False

        if self._max_size > 0 and func.size > self._max_size:
            return False

        if self._address_range:
            start, end = self._address_range
            if not (start <= func.address <= end):
                return False

        return True

    def filter_functions(self, functions: list[TUIFunction]) -> list[TUIFunction]:
        """Filter list of functions."""
        return [f for f in functions if self.matches(f)]

    def clear(self) -> None:
        """Clear all filters."""
        self._pattern = ""
        self._min_size = 0
        self._max_size = 0
        self._address_range = None


class DiffView:
    """
    Display before/after diff view for mutations.

    Shows disassembly changes with syntax highlighting.
    """

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._mutations: list[TUIMutation] = []
        self._current_idx: int = 0

    def set_mutations(self, mutations: list[TUIMutation]) -> None:
        """Set mutations to display."""
        self._mutations = mutations
        self._current_idx = 0

    def next(self) -> bool:
        """Go to next mutation. Returns True if successful."""
        if self._current_idx < len(self._mutations) - 1:
            self._current_idx += 1
            return True
        return False

    def previous(self) -> bool:
        """Go to previous mutation. Returns True if successful."""
        if self._current_idx > 0:
            self._current_idx -= 1
            return True
        return False

    def current(self) -> TUIMutation | None:
        """Get current mutation."""
        if 0 <= self._current_idx < len(self._mutations):
            return self._mutations[self._current_idx]
        return None

    def render(self) -> None:
        """Render the diff view."""
        if RICH_AVAILABLE:
            self._render_rich()
        else:
            self._render_basic()

    def _render_rich(self) -> None:
        """Render diff view with rich formatting."""
        if not self._mutations:
            self.console.print("[yellow]No mutations to display[/yellow]")
            return

        mutation = self._mutations[self._current_idx]

        self.console.print(f"\n[bold]Mutation {self._current_idx + 1} of {len(self._mutations)}[/bold]")
        self.console.print(f"[cyan]Function:[/cyan] {mutation.function or 'unknown'}")
        self.console.print(f"[cyan]Address:[/cyan] 0x{mutation.address:x}")
        self.console.print(f"[cyan]Pass:[/cyan] {mutation.pass_name}")

        if mutation.description:
            self.console.print(f"[dim]{mutation.description}[/dim]")

        orig_hex = mutation.original_bytes.hex() if mutation.original_bytes else "N/A"
        mut_hex = mutation.mutated_bytes.hex() if mutation.mutated_bytes else "N/A"

        table = Table(title="Bytes Diff", show_header=True)
        table.add_column("Type", style="cyan")
        table.add_column("Bytes", style="green")

        table.add_row("Original", orig_hex)
        table.add_row("Mutated", mut_hex)

        self.console.print(table)

        if mutation.original_bytes and mutation.mutated_bytes:
            diff_table = Table(title="Byte Differences", show_header=True)
            diff_table.add_column("Offset", style="dim")
            diff_table.add_column("Original", style="red")
            diff_table.add_column("Mutated", style="green")
            diff_table.add_column("Status", style="yellow")

            max_len = max(len(mutation.original_bytes), len(mutation.mutated_bytes))
            for i in range(min(max_len, 16)):  # Show up to 16 bytes
                orig_byte = mutation.original_bytes[i : i + 1].hex() if i < len(mutation.original_bytes) else "--"
                mut_byte = mutation.mutated_bytes[i : i + 1].hex() if i < len(mutation.mutated_bytes) else "--"

                if orig_byte != mut_byte:
                    status = "changed"
                else:
                    status = "same"

                diff_table.add_row(f"0x{i:x}", orig_byte, mut_byte, status)

            self.console.print(diff_table)

        self.console.print("\n[dim]n: next | p: previous | q: quit[/dim]")

    def _render_basic(self) -> None:
        """Render diff view with basic formatting."""
        if not self._mutations:
            print("No mutations to display")
            return

        mutation = self._mutations[self._current_idx]

        print(f"\nMutation {self._current_idx + 1} of {len(self._mutations)}")
        print(f"Function: {mutation.function or 'unknown'}")
        print(f"Address: 0x{mutation.address:x}")
        print(f"Pass: {mutation.pass_name}")

        if mutation.description:
            print(f"  {mutation.description}")

        orig_hex = mutation.original_bytes.hex() if mutation.original_bytes else "N/A"
        mut_hex = mutation.mutated_bytes.hex() if mutation.mutated_bytes else "N/A"

        print(f"\nOriginal: {orig_hex}")
        print(f"Mutated:  {mut_hex}")
        print("\nn: next | p: previous | q: quit")

    def render_summary(self) -> None:
        """Render summary of all mutations."""
        if not self._mutations:
            self.console.print("[yellow]No mutations to summarize[/yellow]")
            return

        if RICH_AVAILABLE:
            table = Table(title="Mutation Summary")
            table.add_column("#", style="dim")
            table.add_column("Address", style="cyan")
            table.add_column("Function", style="green")
            table.add_column("Pass", style="yellow")
            table.add_column("Size", style="magenta")

            for i, mut in enumerate(self._mutations):
                table.add_row(
                    str(i + 1),
                    f"0x{mut.address:x}",
                    mut.function or "unknown",
                    mut.pass_name,
                    str(len(mut.mutated_bytes)) if mut.mutated_bytes else "0",
                )

            self.console.print(table)
        else:
            print("\nMutation Summary:")
            for i, mut in enumerate(self._mutations):
                print(f"  {i + 1}. 0x{mut.address:x} - {mut.function or 'unknown'} - {mut.pass_name}")

    def render_disasm_diff(self) -> None:
        """Render disassembly diff view with side-by-side comparison."""
        if not self._mutations:
            self.console.print("[yellow]No mutations to display[/yellow]")
            return

        mutation = self._mutations[self._current_idx]

        if RICH_AVAILABLE:
            self._render_disasm_rich(mutation)
        else:
            self._render_disasm_basic(mutation)

    def _render_disasm_rich(self, mutation: TUIMutation) -> None:
        """Render disassembly diff with rich formatting."""
        self.console.print(
            f"\n[bold]Disassembly Diff - Mutation {self._current_idx + 1} of {len(self._mutations)}[/bold]"
        )
        self.console.print(f"[cyan]Function:[/cyan] {mutation.function or 'unknown'}")
        self.console.print(f"[cyan]Address:[/cyan] 0x{mutation.address:x}")
        self.console.print(f"[cyan]Pass:[/cyan] {mutation.pass_name}")

        if mutation.description:
            self.console.print(f"[dim]{mutation.description}[/dim]")

        orig_lines = mutation.original_disasm or []
        mut_lines = mutation.mutated_disasm or []

        if not orig_lines and not mut_lines:
            self.console.print("[yellow]No disassembly available[/yellow]")
            self._render_rich()
            return

        max_lines = max(len(orig_lines), len(mut_lines), 1)

        table = Table(title="Disassembly Comparison", show_header=True, expand=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Original", style="red", ratio=1)
        table.add_column("Mutated", style="green", ratio=1)
        table.add_column("Status", style="yellow", width=8)

        for i in range(max_lines):
            orig_line = orig_lines[i] if i < len(orig_lines) else ""
            mut_line = mut_lines[i] if i < len(mut_lines) else ""

            if orig_line == mut_line:
                status = "same"
            elif not orig_line:
                status = "added"
            elif not mut_line:
                status = "removed"
            else:
                status = "changed"

            table.add_row(
                str(i + 1),
                orig_line[:50] if orig_line else "",
                mut_line[:50] if mut_line else "",
                status,
            )

        self.console.print(table)

        changed_count = sum(
            1
            for i in range(max_lines)
            if (i < len(orig_lines) and i < len(mut_lines) and orig_lines[i] != mut_lines[i])
            or (i >= len(orig_lines) and i < len(mut_lines))
            or (i < len(orig_lines) and i >= len(mut_lines))
        )
        self.console.print(f"\n[bold]Stats:[/bold] {changed_count} lines changed")

        self._render_byte_diff_summary(mutation)

    def _render_byte_diff_summary(self, mutation: TUIMutation) -> None:
        """Render a summary of byte-level differences."""
        orig_bytes = mutation.original_bytes or b""
        mut_bytes = mutation.mutated_bytes or b""

        if orig_bytes == mut_bytes:
            return

        diff_count = 0
        for i in range(max(len(orig_bytes), len(mut_bytes))):
            orig_byte = orig_bytes[i] if i < len(orig_bytes) else None
            mut_byte = mut_bytes[i] if i < len(mut_bytes) else None

            if orig_byte != mut_byte:
                diff_count += 1

        if diff_count > 0:
            self.console.print(f"[dim]Byte changes: {diff_count} / {max(len(orig_bytes), len(mut_bytes))} bytes[/dim]")

    def _render_disasm_basic(self, mutation: TUIMutation) -> None:
        """Render disassembly diff with basic formatting."""
        print(f"\nDisassembly Diff - Mutation {self._current_idx + 1} of {len(self._mutations)}")
        print(f"Function: {mutation.function or 'unknown'}")
        print(f"Address: 0x{mutation.address:x}")
        print(f"Pass: {mutation.pass_name}")

        if mutation.description:
            print(f"  {mutation.description}")

        orig_lines = mutation.original_disasm or []
        mut_lines = mutation.mutated_disasm or []

        if not orig_lines and not mut_lines:
            print("No disassembly available")
            self._render_basic()
            return

        max_lines = max(len(orig_lines), len(mut_lines), 1)

        print(f"\n{'#':<3} {'Original':<40} {'Mutated':<40} {'Status'}")
        print("-" * 100)

        for i in range(max_lines):
            orig_line = orig_lines[i] if i < len(orig_lines) else ""
            mut_line = mut_lines[i] if i < len(mut_lines) else ""

            if orig_line == mut_line:
                status = "same"
            elif not orig_line:
                status = "added"
            elif not mut_line:
                status = "removed"
            else:
                status = "changed"

            orig_display = orig_line[:38] if orig_line else ""
            mut_display = mut_line[:38] if mut_line else ""

            print(f"{i + 1:<3} {orig_display:<40} {mut_display:<40} {status}")

        print("\nn: next | p: previous | d: bytes | q: quit")


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
