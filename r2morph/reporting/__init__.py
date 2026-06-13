"""
Reporting subpackage for report building, filtering, and rendering.

The package root stays thin and resolves symbols lazily so importing
``r2morph.reporting`` does not eagerly pull the whole reporting graph
into memory.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from r2morph.reporting._public_api import LAZY_EXPORTS as _LAZY_EXPORTS
from r2morph.reporting._public_api import LAZY_RENDERING_NAMES as _LAZY_RENDERING_NAMES
from r2morph.reporting._public_api import __all__ as __all__


def __getattr__(name: str) -> Any:
    """Resolve public reporting symbols lazily on first access."""
    if name in _LAZY_RENDERING_NAMES:
        value = getattr(import_module("r2morph.reporting.report_rendering"), name)
        globals()[name] = value
        return value
    if name in _LAZY_EXPORTS:
        module_name, attr_name = _LAZY_EXPORTS[name]
        value = getattr(import_module(module_name), attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
