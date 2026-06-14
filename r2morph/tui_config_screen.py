"""Interactive configuration screen for the TUI."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.tui_pass_config import TUIPassConfig
from r2morph.tui_presets import CONFIG_OPTIONS, CONFIG_TYPES, DEFAULT_PASS_CONFIGS
from r2morph.tui_rendering_helpers import build_config_basic_lines, build_config_rich_rows

logger = logging.getLogger(__name__)

Console: Any
try:
    from rich.console import Console
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class _FallbackConsole:
        def print(self, *args: Any, **kwargs: Any) -> None:
            print(*args)

    Console = _FallbackConsole
    Table = None


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
