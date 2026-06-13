"""
Analysis module for binary analysis utilities.
"""

# Symbolic execution and advanced analysis remain lazily loaded because the
# optional angr stack is heavy and should not be imported for unrelated core
# analysis workflows.

from __future__ import annotations

from importlib import import_module
from typing import Any as _Any

from r2morph.analysis._public_api import LAZY_EXPORTS as _LAZY_EXPORTS
from r2morph.analysis._public_api import SYMBOLIC_NAMES as _SYMBOLIC_NAMES
from r2morph.analysis._public_api import __all__ as __all__


def __getattr__(name: str) -> _Any:
    if name in _SYMBOLIC_NAMES:
        try:
            from r2morph.analysis import symbolic as _symbolic
        except ImportError:
            resolved: dict[str, _Any] = {
                "AngrBridge": None,
                "ConstraintSolver": None,
                "PathExplorer": None,
                "StateManager": None,
                "SyntiaFramework": None,
                "SYNTIA_AVAILABLE": False,
                "SYMBOLIC_AVAILABLE": False,
            }
        else:
            resolved = {
                "AngrBridge": _symbolic.AngrBridge,
                "ConstraintSolver": _symbolic.ConstraintSolver,
                "PathExplorer": _symbolic.PathExplorer,
                "StateManager": _symbolic.StateManager,
                "SyntiaFramework": _symbolic.SyntiaFramework,
                "SYNTIA_AVAILABLE": _symbolic.SYNTIA_AVAILABLE,
                "SYMBOLIC_AVAILABLE": True,
            }
        globals().update(resolved)
        return resolved[name]

    if name in _LAZY_EXPORTS:
        module_name, attr_name = _LAZY_EXPORTS[name]
        value = getattr(import_module(module_name), attr_name)
        globals()[name] = value
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))

