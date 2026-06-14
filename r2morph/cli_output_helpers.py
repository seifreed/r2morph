"""Pure formatting helpers for CLI command output."""

from __future__ import annotations

from typing import Any


def build_binary_analysis_rows(stats: dict[str, Any]) -> list[tuple[str, str]]:
    """Build the binary analysis table rows in display order."""
    arch = stats["architecture"]
    return [
        ("Architecture", f"{arch['arch']} ({arch['bits']}-bit)"),
        ("Format", arch["format"]),
        ("Endian", arch["endian"]),
        ("Total Functions", str(stats["total_functions"])),
        ("Total Instructions", str(stats["total_instructions"])),
        ("Total Basic Blocks", str(stats["total_basic_blocks"])),
        ("Total Code Size", f"{stats['total_code_size']} bytes"),
        ("Avg Function Size", f"{stats['avg_function_size']:.2f} bytes"),
        ("Avg Instructions/Function", f"{stats['avg_instructions_per_function']:.2f}"),
    ]


def build_function_rows(funcs: list[Any], *, limit: int) -> list[tuple[str, str, str, str]]:
    """Build the binary functions table rows in display order."""
    rows: list[tuple[str, str, str, str]] = []
    for func in funcs[:limit]:
        rows.append(
            (
                f"0x{func.address:x}",
                func.name,
                str(func.size),
                str(func.get_instructions_count()),
            )
        )
    return rows


def build_function_limit_notice(limit: int, total: int) -> str | None:
    """Build the notice shown when the function list is truncated."""
    if total <= limit:
        return None
    return f"Showing {limit} of {total} functions. Use --limit to show more."

