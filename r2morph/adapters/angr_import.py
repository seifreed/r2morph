"""Optional angr import boundary."""

from __future__ import annotations

import importlib
import warnings
from dataclasses import dataclass
from typing import Any

_PY314_CTYPES_PACK_WARNING = r"Due to '_pack_', the '.*' Structure.*"


@dataclass(frozen=True)
class AngrImport:
    available: bool
    angr: Any | None = None
    claripy: Any | None = None
    project: Any | None = None
    cfg_fast: Any | None = None
    exploration_technique: Any | None = None


def import_angr_modules(
    *,
    claripy: bool = False,
    project: bool = False,
    cfg_fast: bool = False,
    exploration_technique: bool = False,
) -> AngrImport:
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=_PY314_CTYPES_PACK_WARNING, category=DeprecationWarning)
            angr_module = importlib.import_module("angr")
            claripy_module = importlib.import_module("claripy") if claripy else None
            project_class = angr_module.Project if project else None
            cfg_fast_class = importlib.import_module("angr.analyses").CFGFast if cfg_fast else None
            technique_class = (
                importlib.import_module("angr.exploration_techniques").ExplorationTechnique
                if exploration_technique
                else None
            )
    except ImportError:
        return AngrImport(available=False)

    return AngrImport(
        available=True,
        angr=angr_module,
        claripy=claripy_module,
        project=project_class,
        cfg_fast=cfg_fast_class,
        exploration_technique=technique_class,
    )
