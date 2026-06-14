"""Static pattern catalogs for switch table analysis."""

from __future__ import annotations

JUMP_TABLE_PATTERNS = [
    (r"jmp\s+\[([a-z]+)\s*\*\s*(\d+)\s*\+\s*(0x[0-9a-f]+)\]", "indexed_scaled_offset"),
    (r"jmp\s+\[([a-z]+)\s*\*\s*(\d+)\]", "indexed_scaled"),
    (r"jmp\s+\[([a-z]+)\s*\+\s*(0x[0-9a-f]+)\]", "indexed_offset"),
    (r"jmp\s+\[([a-z]+)\]", "indexed"),
    (r"jmp\s+([a-z]+)", "register"),
    (r"jmp\s+(0x[0-9a-f]+)", "absolute"),
]

TAIL_CALL_PATTERNS = [
    (r"jmp\s+([a-z]+\.[a-zA-Z0-9_]+)", "symbolic"),
    (r"jmp\s+(0x[0-9a-f]+)", "absolute"),
]

PLT_PATTERNS = [
    r"jmp\s+\[rip\s*\+\s*0x[0-9a-f]+\]",
    r"jmp\s+\[([a-z]+)\s*\+\s*0x[0-9a-f]+\].*;.*plt",
]
