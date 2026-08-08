"""Dict-like mapping helpers for report context dataclasses."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import Field, asdict, fields, is_dataclass
from typing import Any


def _dataclass_fields(obj: object) -> tuple[Field[Any], ...]:
    if not is_dataclass(obj):
        raise TypeError("report context must be a dataclass")
    return fields(obj)


def report_context_getitem(obj: object, key: str) -> Any:
    return getattr(obj, key)


def report_context_contains(obj: object, key: str) -> bool:
    return hasattr(obj, key) and key in {f.name for f in _dataclass_fields(obj)}


def report_context_get(obj: object, key: str, default: Any = None) -> Any:
    try:
        return getattr(obj, key)
    except AttributeError:
        return default


def report_context_keys(obj: object) -> list[str]:
    return [f.name for f in _dataclass_fields(obj)]


def report_context_values(obj: object) -> list[Any]:
    return [getattr(obj, f.name) for f in _dataclass_fields(obj)]


def report_context_items(obj: object) -> list[tuple[str, Any]]:
    return [(f.name, getattr(obj, f.name)) for f in _dataclass_fields(obj)]


def report_context_iter(obj: object) -> Iterator[str]:
    return iter(report_context_keys(obj))


def report_context_to_dict(obj: object) -> dict[str, Any]:
    if not is_dataclass(obj) or isinstance(obj, type):
        raise TypeError("report context must be a dataclass instance")
    return asdict(obj)
