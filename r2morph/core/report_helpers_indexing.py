"""Shared indexing helper for per-pass report rows."""

from __future__ import annotations

from typing import Any


def _index_rows_by_pass_name(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index report rows by their pass name, dropping rows without one."""
    return {str(row.get("pass_name")): dict(row) for row in rows if row.get("pass_name")}
