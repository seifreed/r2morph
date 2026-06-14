"""Pure row and line builders for TUI rendering."""

from __future__ import annotations

from typing import Any

from r2morph.tui_presets import CONFIG_OPTIONS, CONFIG_TYPES, DEFAULT_PASS_CONFIGS, PASS_DESCRIPTIONS


def build_main_menu_actions() -> list[tuple[str, str, str]]:
    """Build the main screen actions in display order."""
    return [
        ("F", "Select Functions", "Choose functions to mutate"),
        ("P", "Select Passes", "Choose mutation passes"),
        ("V", "Preview", "Preview mutations"),
        ("E", "Execute", "Run mutations"),
        ("Q", "Quit", "Exit TUI"),
    ]


def build_function_rich_rows(functions: list[Any], *, limit: int = 50) -> list[tuple[str, str, str, str]]:
    """Build the rich function rows in display order."""
    return [
        ("X" if func.selected else " ", f"0x{func.address:x}", func.name, str(func.size))
        for func in functions[:limit]
    ]


def build_function_basic_lines(functions: list[Any], *, limit: int = 30) -> list[str]:
    """Build the basic-mode function lines in display order."""
    return [
        f"{'[X]' if func.selected else '[ ]'} {i}: 0x{func.address:x} {func.name} ({func.size} bytes)"
        for i, func in enumerate(functions[:limit])
    ]


def build_pass_rich_rows(passes: list[Any]) -> list[tuple[str, str, str, str]]:
    """Build the rich pass rows in display order."""
    rows: list[tuple[str, str, str, str]] = []
    for mp in passes:
        status = "stable" if mp.is_stable else "experimental"
        status_style = "green" if mp.is_stable else "yellow"
        desc, _ = PASS_DESCRIPTIONS.get(mp.name, (mp.description, mp.is_stable))
        rows.append(("X" if mp.selected else " ", mp.name, f"[{status_style}]{status}[/{status_style}]", desc))
    return rows


def build_pass_basic_lines(passes: list[Any]) -> list[str]:
    """Build the basic-mode pass lines in display order."""
    lines: list[str] = []
    for i, mp in enumerate(passes):
        status = "stable" if mp.is_stable else "experimental"
        desc, _ = PASS_DESCRIPTIONS.get(mp.name, (mp.description, mp.is_stable))
        lines.append(f"{'[X]' if mp.selected else '[ ]'} {i}: {mp.name} ({status}) - {desc}")
    return lines


def build_config_rich_rows(
    pass_name: str,
    config: dict[str, Any] | None = None,
) -> list[tuple[str, str, str, str]]:
    """Build the rich configuration rows in display order."""
    current_config = config or DEFAULT_PASS_CONFIGS.get(pass_name, {})
    config_types = CONFIG_TYPES.get(pass_name, {})
    config_options = CONFIG_OPTIONS.get(pass_name, {})

    rows: list[tuple[str, str, str, str]] = []
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
        rows.append((key, type_str, current_str, options_str))
    return rows


def build_config_basic_lines(
    pass_name: str,
    config: dict[str, Any] | None = None,
) -> list[str]:
    """Build the basic-mode configuration lines in display order."""
    current_config = config or DEFAULT_PASS_CONFIGS.get(pass_name, {})
    return [f"  {key}: {val}" for key, val in current_config.items()]


def build_preview_rich_rows(
    mutations: list[Any],
    *,
    start: int,
    end: int,
) -> list[tuple[str, str, str, str, str]]:
    """Build the rich preview rows in display order."""
    rows: list[tuple[str, str, str, str, str]] = []
    for m in mutations[start:end]:
        rows.append(
            (
                f"0x{m.address:x}",
                (m.function or "unknown")[:20],
                m.pass_name,
                m.original_bytes.hex()[:16],
                m.mutated_bytes.hex()[:16],
            )
        )
    return rows


def build_preview_basic_lines(
    mutations: list[Any],
    *,
    start: int,
    end: int,
) -> list[str]:
    """Build the basic preview lines in display order."""
    lines: list[str] = []
    for m in mutations[start:end]:
        func = m.function or "unknown"
        lines.append(f"0x{m.address:x} | {func[:20]:20} | {m.pass_name:15}")
        lines.append(f"  Original: {m.original_bytes.hex()[:16]}")
        lines.append(f"  Mutated:  {m.mutated_bytes.hex()[:16]}")
        if m.description:
            lines.append(f"  Note:     {m.description}")
        lines.append("")
    return lines

