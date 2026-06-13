"""Public package surface for r2morph.

The package root stays intentionally thin: it exposes the stable version
metadata immediately and loads heavyweight runtime symbols lazily so that
``import r2morph`` does not pull the whole execution graph into memory.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__version__ = "0.3.0"

__author__ = "r2morph contributors"
__license__ = "MIT"

_LAZY_EXPORTS = {
    "Binary": ("r2morph.core.binary", "Binary"),
    "MorphEngine": ("r2morph.core.engine", "MorphEngine"),
    "Pipeline": ("r2morph.pipeline.pipeline", "Pipeline"),
}

if TYPE_CHECKING:  # pragma: no cover - import-time typing only
    from r2morph.core.binary import Binary
    from r2morph.core.engine import MorphEngine
    from r2morph.pipeline.pipeline import Pipeline

__all__ = ["Binary", "MorphEngine", "Pipeline", "__version__"]


def __getattr__(name: str) -> Any:
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _LAZY_EXPORTS[name]
    value = getattr(import_module(module_name), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
