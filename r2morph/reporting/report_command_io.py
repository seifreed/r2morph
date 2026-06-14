"""I/O helpers for report command handling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich import print as rprint


def load_report_payload(report_file: Path) -> dict[str, Any]:
    """Load a persisted report payload from disk."""
    with open(report_file, encoding="utf-8") as handle:
        return json.load(handle)


def emit_report_output(
    output_format: str,
    output: Path | None,
    mutations: list[dict[str, Any]],
    validations: list[dict[str, Any]],
    binary_path: str,
) -> None:
    """Emit the requested report output format."""
    if output_format.lower() != "sarif":
        return

    from r2morph.reporting.sarif_formatter import format_as_sarif

    sarif_report = format_as_sarif(mutations, validations, binary_path)
    sarif_json = sarif_report.to_json()
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(sarif_json)
        rprint(f"[green]SARIF report written to[/green] {output}")
    else:
        print(sarif_json)
