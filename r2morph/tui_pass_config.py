"""Pass configuration state for the TUI."""

from __future__ import annotations

from typing import Any

from r2morph.tui_presets import DEFAULT_PASS_CONFIGS


class TUIPassConfig:
    """Configuration options for mutation passes."""

    def __init__(self, pass_name: str, config: dict[str, Any] | None = None) -> None:
        self.pass_name = pass_name
        self.config = config or DEFAULT_PASS_CONFIGS.get(pass_name, {}).copy()

    def get_option(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    def set_option(self, key: str, value: Any) -> None:
        self.config[key] = value
