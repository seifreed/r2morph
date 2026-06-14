"""Projection helpers for PE handlers."""

from __future__ import annotations

from typing import Any


def project_imports(binary: Any) -> list[dict]:
    """Convert LIEF imports into plain dictionaries."""
    imports: list[dict] = []
    for entry in binary.imports:
        items = []
        for func in entry.entries:
            if func.name:
                items.append(func.name)
            else:
                items.append(func.ordinal)
        imports.append({"library": entry.name, "entries": items})
    return imports


def project_exports(binary: Any) -> list[dict]:
    """Convert LIEF exports into plain dictionaries."""
    exports: list[dict] = []
    for func in binary.exported_functions:
        exports.append(
            {
                "name": func.name if hasattr(func, "name") else None,
                "address": func.address if hasattr(func, "address") else None,
                "ordinal": func.ordinal if hasattr(func, "ordinal") else None,
            }
        )
    return exports


def project_relocations(binary: Any) -> list[dict]:
    """Convert LIEF relocations into plain dictionaries."""
    relocations: list[dict] = []
    for reloc in binary.relocations:
        relocations.append(
            {
                "address": reloc.address,
                "size": reloc.size,
                "type": str(reloc.type),
            }
        )
    return relocations


__all__ = ["project_exports", "project_imports", "project_relocations"]
