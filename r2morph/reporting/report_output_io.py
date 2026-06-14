"""Report output I/O helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


def emit_report_payload(
    *,
    filtered_payload: dict[str, Any],
    output: Path | None,
    summary_only: bool,
    console_instance: Console | None = None,
) -> None:
    """Write and/or print a filtered report payload."""
    c = console_instance or console
    if output is not None:
        output.write_text(json.dumps(filtered_payload, indent=2), encoding="utf-8")
        c.print(f"[cyan]Filtered report written:[/cyan] {output}")
    if not summary_only:
        c.print_json(json.dumps(filtered_payload))
