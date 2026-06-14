"""Dict-like mapping helpers for report context dataclasses."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, fields
from typing import Any


def report_context_getitem(obj: object, key: str) -> Any:
    return getattr(obj, key)


def report_context_contains(obj: object, key: str) -> bool:
    return hasattr(obj, key) and key in {f.name for f in fields(obj)}


def report_context_get(obj: object, key: str, default: Any = None) -> Any:
    try:
        return getattr(obj, key)
    except AttributeError:
        return default


def report_context_keys(obj: object) -> list[str]:
    return [f.name for f in fields(obj)]


def report_context_values(obj: object) -> list[Any]:
    return [getattr(obj, f.name) for f in fields(obj)]


def report_context_items(obj: object) -> list[tuple[str, Any]]:
    return [(f.name, getattr(obj, f.name)) for f in fields(obj)]


def report_context_iter(obj: object) -> Iterator[str]:
    return iter(report_context_keys(obj))


def report_context_to_dict(obj: object) -> dict[str, Any]:
    return asdict(obj)
