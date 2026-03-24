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

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable
import re


class _FallbackConsole:
    """Fallback console when rich is not available."""

    def print(self, *args: Any, **kwargs: Any) -> None:
        """Print to stdout."""
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

        actions = [
            ("F", "Select Functions", "Choose functions to mutate"),
            ("P", "Select Passes", "Choose mutation passes"),
            ("V", "Preview", "Preview mutations"),
            ("E", "Execute", "Run mutations"),
            ("Q", "Quit", "Exit TUI"),
        ]

        for key, action, desc in actions:
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

    def render(self, functions: list[TUIFunction]) -> None:
        if RICH_AVAILABLE:
            self._render_rich(functions)
        else:
            self._render_basic(functions)

    def _render_rich(self, functions: list[TUIFunction]) -> None:
        table = Table(title="Select Functions")
        table.add_column("[", style="cyan", width=3)
        table.add_column("Address", style="yellow")
        table.add_column("Name", style="green")
        table.add_column("Size", style="blue")

        for func in functions[:50]:
            marker = "X" if func.selected else " "
            table.add_row(marker, f"0x{func.address:x}", func.name, str(func.size))

        self.console.print(table)
        self.console.print("\n[Enter number to toggle, A for all, N for none, C to continue]")

    def _render_basic(self, functions: list[TUIFunction]) -> None:
        print("\n=== Select Functions ===\n")
        for i, func in enumerate(functions[:30]):
            marker = "[X]" if func.selected else "[ ]"
            print(f"{marker} {i}: 0x{func.address:x} {func.name} ({func.size} bytes)")
        print("\n[Enter number to toggle, A for all, N for none, C to continue]")


class TUIPassScreen:
    PASS_DESCRIPTIONS: dict[str, tuple[str, bool]] = {
        "nop": ("Insert benign NOP instructions", True),
        "substitute": ("Replace instructions with equivalents", True),
        "register": ("Substitute registers safely", True),
        "block": ("Reorder basic blocks", False),
        "dead-code": ("Inject dead code sequences", False),
        "opaque": ("Insert opaque predicates", False),
        "expand": ("Expand instructions to longer forms", False),
        "cff": ("Flatten control flow", False),
    }

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, passes: list[TUIPass]) -> None:
        if RICH_AVAILABLE:
            self._render_rich(passes)
        else:
            self._render_basic(passes)

    def _render_rich(self, passes: list[TUIPass]) -> None:
        table = Table(title="Select Mutation Passes")
        table.add_column("[", style="cyan", width=3)
        table.add_column("Pass", style="yellow")
        table.add_column("Status", style="blue")
        table.add_column("Description")

        for mp in passes:
            marker = "X" if mp.selected else " "
            status = "stable" if mp.is_stable else "experimental"
            status_style = "green" if mp.is_stable else "yellow"
            desc, _ = self.PASS_DESCRIPTIONS.get(mp.name, (mp.description, mp.is_stable))
            table.add_row(marker, mp.name, f"[{status_style}]{status}[/{status_style}]", desc)

        self.console.print(table)
        self.console.print("\n[Enter number to toggle, A for all, N for none, C to continue]")

    def _render_basic(self, passes: list[TUIPass]) -> None:
        print("\n=== Select Mutation Passes ===\n")
        for i, mp in enumerate(passes):
            marker = "[X]" if mp.selected else "[ ]"
            status = "stable" if mp.is_stable else "experimental"
            desc, _ = self.PASS_DESCRIPTIONS.get(mp.name, (mp.description, mp.is_stable))
            print(f"{marker} {i}: {mp.name} ({status}) - {desc}")
        print("\n[Enter number to toggle, A for all, N for none, C to continue]")


class TUIPassConfig:
    """Configuration options for mutation passes."""

    DEFAULT_CONFIGS: dict[str, dict[str, Any]] = {
        "nop": {
            "max_nops": 3,
            "use_equiv": True,
            "avoid_critical": True,
        },
        "substitute": {
            "x86_equiv": True,
            "arm_equiv": True,
            "preserve_semantics": True,
        },
        "register": {
            "preserve_calling_conv": True,
            "preserve_callee_saved": True,
            "max_substitutions": 2,
        },
        "block": {
            "max_blocks": 10,
            "preserve_entry": True,
        },
        "dead-code": {
            "max_instructions": 5,
            "use_opaque": True,
        },
        "opaque": {
            "predicate_type": "true",
            "complexity": "medium",
        },
        "expand": {
            "max_expansion": 3,
            "preserve_flags": True,
        },
        "cff": {
            "dispatcher_style": "switch",
            "max_depth": 3,
        },
    }

    def __init__(self, pass_name: str, config: dict[str, Any] | None = None) -> None:
        self.pass_name = pass_name
        self.config = config or self.DEFAULT_CONFIGS.get(pass_name, {}).copy()

    def get_option(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    def set_option(self, key: str, value: Any) -> None:
        self.config[key] = value


class TUIConfigScreen:
    """Interactive configuration screen for pass options."""

    CONFIG_TYPES: dict[str, dict[str, type]] = {
        "nop": {"max_nops": int, "use_equiv": bool, "avoid_critical": bool},
        "substitute": {"x86_equiv": bool, "arm_equiv": bool, "preserve_semantics": bool},
        "register": {"preserve_calling_conv": bool, "preserve_callee_saved": bool, "max_substitutions": int},
        "block": {"max_blocks": int, "preserve_entry": bool},
        "dead-code": {"max_instructions": int, "use_opaque": bool},
        "opaque": {"predicate_type": str, "complexity": str},
        "expand": {"max_expansion": int, "preserve_flags": bool},
        "cff": {"dispatcher_style": str, "max_depth": int},
    }

    CONFIG_OPTIONS: dict[str, dict[str, list[str]]] = {
        "opaque": {"predicate_type": ["true", "false", "mixed"], "complexity": ["low", "medium", "high"]},
        "cff": {"dispatcher_style": ["switch", "jump_table", "nested"]},
    }

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
        current_config = config or TUIPassConfig.DEFAULT_CONFIGS.get(pass_name, {})
        config_types = self.CONFIG_TYPES.get(pass_name, {})
        config_options = self.CONFIG_OPTIONS.get(pass_name, {})

        table = Table(title=f"Configure {pass_name}")
        table.add_column("Option", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Current", style="green")
        table.add_column("Options", style="yellow")

        for key, val in current_config.items():
            val_type = config_types.get(key, type(val))
            type_str = val_type.__name__

            if key in config_options:
                options_str = " | ".join(config_options[key])
            elif val_type is bool:
                options_str = "true | false"
            elif val_type is int:
                options_str = "<number>"
            else:
                options_str = "<value>"

            current_str = str(val) if not isinstance(val, bool) else ("true" if val else "false")
            table.add_row(key, type_str, current_str, options_str)

        self.console.print(table)
        self.console.print("\n[Enter option=value to change, D for defaults, C to continue]")

    def _render_basic(self, pass_name: str, config: dict[str, Any] | None = None) -> None:
        current_config = config or TUIPassConfig.DEFAULT_CONFIGS.get(pass_name, {})
        print(f"\n=== Configure {pass_name} ===\n")

        for key, val in current_config.items():
            print(f"  {key}: {val}")

        print("\n[Enter option=value to change, D for defaults, C to continue]")

    def handle_input(self, key_input: str, pass_name: str, current_config: dict[str, Any]) -> dict[str, Any]:
        config = current_config.copy()

        if key_input.lower() == "d":
            return TUIPassConfig.DEFAULT_CONFIGS.get(pass_name, {}).copy()

        if "=" in key_input:
            parts = key_input.split("=", 1)
            if len(parts) == 2:
                option = parts[0].strip()
                value = parts[1].strip()

                config_types = self.CONFIG_TYPES.get(pass_name, {})
                expected_type = config_types.get(option, str)

                if expected_type is bool:
                    config[option] = value.lower() in ("true", "1", "yes", "on")
                elif expected_type is int:
                    try:
                        config[option] = int(value)
                    except ValueError:
                        pass
                else:
                    config[option] = value

        return config

    def configure_all_passes(self, passes: list[TUIPass]) -> dict[str, dict[str, Any]]:
        configs: dict[str, dict[str, Any]] = {}
        for p in passes:
            if p.selected and p.configurable:
                configs[p.name] = self.get_config(p.name).config.copy()
        return configs


class TUIPreviewScreen:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, mutations: list[TUIMutation], page: int = 0, page_size: int = 10) -> None:
        if RICH_AVAILABLE:
            self._render_rich(mutations, page, page_size)
        else:
            self._render_basic(mutations, page, page_size)

    def _render_rich(self, mutations: list[TUIMutation], page: int, page_size: int) -> None:
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

        for m in mutations[start:end]:
            orig_hex = m.original_bytes.hex()[:16]
            mut_hex = m.mutated_bytes.hex()[:16]
            func = m.function or "unknown"
            table.add_row(
                f"0x{m.address:x}",
                func[:20],
                m.pass_name,
                orig_hex,
                mut_hex,
            )

        layout["mutations"].update(table)

        nav = "[N]ext [P]rev [E]xecute [Q]uit"
        layout["footer"].update(Panel(nav))

        self.console.print(layout)

    def _render_basic(self, mutations: list[TUIMutation], page: int, page_size: int) -> None:
        total_pages = (len(mutations) + page_size - 1) // page_size
        start = page * page_size
        end = min(start + page_size, len(mutations))

        print(f"\n=== Mutation Preview (Page {page + 1}/{max(total_pages, 1)}) ===\n")

        for m in mutations[start:end]:
            orig_hex = m.original_bytes.hex()[:16]
            mut_hex = m.mutated_bytes.hex()[:16]
            func = m.function or "unknown"
            print(f"0x{m.address:x} | {func[:20]:20} | {m.pass_name:15}")
            print(f"  Original: {orig_hex}")
            print(f"  Mutated:  {mut_hex}")
            if m.description:
                print(f"  Note:     {m.description}")
            print()

        print("[N]ext [P]rev [E]xecute [Q]uit")


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
