"""Rendering and configuration helpers for the r2morph TUI."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.tui_pass_config import TUIPassConfig
from r2morph.tui_presets import CONFIG_OPTIONS, CONFIG_TYPES, DEFAULT_PASS_CONFIGS, PASS_DESCRIPTIONS
from r2morph.tui_progress_indicator import TUIProgressIndicator as _TUIProgressIndicator
from r2morph.tui_rendering_helpers import (
    build_config_basic_lines,
    build_config_rich_rows,
    build_function_basic_lines,
    build_function_rich_rows,
    build_main_menu_actions,
    build_pass_basic_lines,
    build_pass_rich_rows,
    build_preview_basic_lines,
    build_preview_rich_rows,
)

logger = logging.getLogger(__name__)

TUIProgressIndicator = _TUIProgressIndicator


class _FallbackConsole:
    """Fallback console when rich is not available."""

    def print(self, *args: Any, **kwargs: Any) -> None:
        print(*args)


Console: Any
try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = _FallbackConsole
    Confirm = Prompt = Layout = Panel = Table = Text = Progress = SpinnerColumn = BarColumn = TextColumn = TimeElapsedColumn = None


class TUIMainScreen:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self) -> None:
        if RICH_AVAILABLE:
            self._render_rich()
        else:
            self._render_basic()

    def _render_rich(self) -> None:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        header_text = Text("r2morph TUI", style="bold cyan")
        layout["header"].update(Panel(header_text))

        table = Table(title="Available Actions")
        table.add_column("Key", style="cyan")
        table.add_column("Action", style="green")
        table.add_column("Description")

        for key, action, desc in build_main_menu_actions():
            table.add_row(key, action, desc)

        layout["body"].update(table)
        footer_text = Text("Press a key to continue", style="dim")
        layout["footer"].update(Panel(footer_text))

        self.console.print(layout)

    def _render_basic(self) -> None:
        print("\n=== r2morph TUI ===\n")
        print("[F] Select Functions - Choose functions to mutate")
        print("[P] Select Passes - Choose mutation passes")
        print("[V] Preview - Preview mutations")
        print("[E] Execute - Run mutations")
        print("[Q] Quit - Exit TUI\n")


class TUIFunctionScreen:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, functions: list[Any]) -> None:
        if RICH_AVAILABLE:
            self._render_rich(functions)
        else:
            self._render_basic(functions)

    def _render_rich(self, functions: list[Any]) -> None:
        table = Table(title="Select Functions")
        table.add_column("[", style="cyan", width=3)
        table.add_column("Address", style="yellow")
        table.add_column("Name", style="green")
        table.add_column("Size", style="blue")

        for marker, address, name, size in build_function_rich_rows(functions):
            table.add_row(marker, address, name, size)

        self.console.print(table)
        self.console.print("\n[Enter number to toggle, A for all, N for none, C to continue]")

    def _render_basic(self, functions: list[Any]) -> None:
        print("\n=== Select Functions ===\n")
        for line in build_function_basic_lines(functions):
            print(line)
        print("\n[Enter number to toggle, A for all, N for none, C to continue]")


class TUIPassScreen:
    PASS_DESCRIPTIONS = PASS_DESCRIPTIONS

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, passes: list[Any]) -> None:
        if RICH_AVAILABLE:
            self._render_rich(passes)
        else:
            self._render_basic(passes)

    def _render_rich(self, passes: list[Any]) -> None:
        table = Table(title="Select Mutation Passes")
        table.add_column("[", style="cyan", width=3)
        table.add_column("Pass", style="yellow")
        table.add_column("Status", style="blue")
        table.add_column("Description")

        for marker, name, status, desc in build_pass_rich_rows(passes):
            table.add_row(marker, name, status, desc)

        self.console.print(table)
        self.console.print("\n[Enter number to toggle, A for all, N for none, C to continue]")

    def _render_basic(self, passes: list[Any]) -> None:
        print("\n=== Select Mutation Passes ===\n")
        for line in build_pass_basic_lines(passes):
            print(line)
        print("\n[Enter number to toggle, A for all, N for none, C to continue]")


class TUIConfigScreen:
    """Interactive configuration screen for pass options."""

    CONFIG_TYPES = CONFIG_TYPES
    CONFIG_OPTIONS = CONFIG_OPTIONS

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._current_pass: str | None = None
        self._configs: dict[str, TUIPassConfig] = {}

    def get_config(self, pass_name: str) -> TUIPassConfig:
        if pass_name not in self._configs:
            self._configs[pass_name] = TUIPassConfig(pass_name)
        return self._configs[pass_name]

    def set_config(self, pass_name: str, config: dict[str, Any]) -> None:
        self._configs[pass_name] = TUIPassConfig(pass_name, config)

    def render(self, pass_name: str, config: dict[str, Any] | None = None) -> None:
        if RICH_AVAILABLE:
            self._render_rich(pass_name, config)
        else:
            self._render_basic(pass_name, config)

    def _render_rich(self, pass_name: str, config: dict[str, Any] | None = None) -> None:
        table = Table(title=f"Configure {pass_name}")
        table.add_column("Option", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Current", style="green")
        table.add_column("Options", style="yellow")

        for key, type_str, current_str, options_str in build_config_rich_rows(pass_name, config):
            table.add_row(key, type_str, current_str, options_str)

        self.console.print(table)
        self.console.print("\n[Enter option=value to change, D for defaults, C to continue]")

    def _render_basic(self, pass_name: str, config: dict[str, Any] | None = None) -> None:
        print(f"\n=== Configure {pass_name} ===\n")

        for line in build_config_basic_lines(pass_name, config):
            print(line)

        print("\n[Enter option=value to change, D for defaults, C to continue]")

    def handle_input(self, key_input: str, pass_name: str, current_config: dict[str, Any]) -> dict[str, Any]:
        config = current_config.copy()

        if key_input.lower() == "d":
            return DEFAULT_PASS_CONFIGS.get(pass_name, {}).copy()

        if "=" in key_input:
            parts = key_input.split("=", 1)
            if len(parts) == 2:
                option = parts[0].strip()
                value = parts[1].strip()

                config_types = CONFIG_TYPES.get(pass_name, {})
                expected_type = config_types.get(option, str)

                if expected_type is bool:
                    config[option] = value.lower() in ("true", "1", "yes", "on")
                elif expected_type is int:
                    try:
                        config[option] = int(value)
                    except ValueError:
                        logger.warning(
                            "Cannot parse %r as int for option %r; keeping previous value",
                            value,
                            option,
                        )
                else:
                    config[option] = value

        return config

    def configure_all_passes(self, passes: list[Any]) -> dict[str, dict[str, Any]]:
        configs: dict[str, dict[str, Any]] = {}
        for p in passes:
            if p.selected and p.configurable:
                configs[p.name] = self.get_config(p.name).config.copy()
        return configs


class TUIPreviewScreen:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, mutations: list[Any], page: int = 0, page_size: int = 10) -> None:
        if RICH_AVAILABLE:
            self._render_rich(mutations, page, page_size)
        else:
            self._render_basic(mutations, page, page_size)

    def _render_rich(self, mutations: list[Any], page: int, page_size: int) -> None:
        total_pages = (len(mutations) + page_size - 1) // page_size
        start = page * page_size
        end = min(start + page_size, len(mutations))

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="mutations"),
            Layout(name="footer", size=3),
        )

        header = Text(f"Mutation Preview (Page {page + 1}/{max(total_pages, 1)})")
        layout["header"].update(Panel(header))

        table = Table()
        table.add_column("Address", style="yellow")
        table.add_column("Function", style="green")
        table.add_column("Pass", style="cyan")
        table.add_column("Original", style="red")
        table.add_column("Mutated", style="blue")

        for address, func, pass_name, orig_hex, mut_hex in build_preview_rich_rows(
            mutations,
            start=start,
            end=end,
        ):
            table.add_row(address, func, pass_name, orig_hex, mut_hex)

        layout["mutations"].update(table)

        nav = "[N]ext [P]rev [E]xecute [Q]uit"
        layout["footer"].update(Panel(nav))

        self.console.print(layout)

    def _render_basic(self, mutations: list[Any], page: int, page_size: int) -> None:
        total_pages = (len(mutations) + page_size - 1) // page_size
        start = page * page_size
        end = min(start + page_size, len(mutations))

        print(f"\n=== Mutation Preview (Page {page + 1}/{max(total_pages, 1)}) ===\n")

        for line in build_preview_basic_lines(mutations, start=start, end=end):
            print(line)

        print("[N]ext [P]rev [E]xecute [Q]uit")
