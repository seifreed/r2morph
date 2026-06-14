"""Entry-point detection helpers for call graph construction."""

from __future__ import annotations

from r2morph.analysis.call_graph import CallGraph
from r2morph.core.binary import Binary


def find_entry_points(binary: Binary, cg: CallGraph) -> list[int]:
    """Find the likely entry-point functions for a call graph."""
    entry_points: list[int] = []

    symbols = getattr(binary, "_symbols", {}) or {}
    entry = symbols.get("entry0")
    if entry:
        entry_addr = entry if isinstance(entry, int) else entry.get("offset", 0)
        if entry_addr in cg.nodes:
            entry_points.append(entry_addr)

    main_sym = symbols.get("main")
    if main_sym:
        main_addr = main_sym if isinstance(main_sym, int) else main_sym.get("offset", 0)
        if main_addr in cg.nodes and main_addr not in entry_points:
            entry_points.append(main_addr)

    init_syms = [symbols.get("__libc_csu_init"), symbols.get("_init")]
    for sym in init_syms:
        if sym:
            addr = sym if isinstance(sym, int) else sym.get("offset", 0)
            if addr in cg.nodes and addr not in entry_points:
                entry_points.append(addr)

    if not entry_points:
        entry_points = cg.get_entry_points()

    return entry_points
