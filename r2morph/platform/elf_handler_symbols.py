"""Symbol-table projection helpers for ELF handlers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from r2morph.platform.elf_structs import MAX_SYMBOLS

logger = logging.getLogger(__name__)


def collect_symbol_tables(binary_path: Path) -> dict[str, list[dict[str, Any]]]:
    """Collect ELF symbol tables via LIEF, or return empty tables if unavailable."""
    try:
        import lief
    except ImportError:
        logger.warning("lief library recommended for symbol table parsing. Install with: pip install lief")
        return {"symtab": [], "dynsym": []}

    try:
        elf = lief.parse(str(binary_path))
        if elf is None or not isinstance(elf, lief.ELF.Binary):
            return {"symtab": [], "dynsym": []}

        result = {
            "symtab": _collect_symbols(elf.symtab_symbols, label="symbol table"),
            "dynsym": _collect_symbols(elf.dynamic_symbols, label="dynamic symbol table"),
        }
        logger.debug(f"Found {len(result['symtab'])} static and {len(result['dynsym'])} dynamic symbols")
        return result
    except Exception as exc:
        logger.error(f"Failed to get symbol tables: {exc}")
        return {"symtab": [], "dynsym": []}


def _collect_symbols(symbols: Any, *, label: str) -> list[dict[str, Any]]:
    """Build symbol dicts from a LIEF symbol iterable, capped at MAX_SYMBOLS."""
    collected: list[dict[str, Any]] = []
    for sym in symbols:
        if len(collected) >= MAX_SYMBOLS:
            logger.warning(f"Truncating {label} at {MAX_SYMBOLS} entries")
            break
        collected.append(
            {
                "name": sym.name,
                "value": sym.value,
                "size": sym.size,
                "type": str(sym.type).split(".")[-1],
                "binding": str(sym.binding).split(".")[-1],
                "visibility": str(sym.visibility).split(".")[-1],
                "shndx": sym.shndx,
            }
        )
    return collected


__all__ = ["collect_symbol_tables"]
