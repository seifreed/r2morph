"""Pure helpers for pointer alias analysis."""

from __future__ import annotations

_BRACKET_PART_COUNT = 2


def extract_lea_target(disasm: str) -> int | None:
    """Extract LEA target from disassembly."""
    parts = disasm.split("[")
    if len(parts) < _BRACKET_PART_COUNT:
        return None

    bracket_content = parts[1].split("]")[0]
    if bracket_content.startswith("0x"):
        try:
            return int(bracket_content, 16)
        except ValueError:
            # Symbolic and register operands are not numeric candidates.
            pass

    return None


def compute_transitive_aliases(points_to: dict[int, set[int]]) -> dict[int, set[int]]:
    """Compute transitive alias closure."""
    aliases = {addr: set(targets) for addr, targets in points_to.items()}

    changed = True
    while changed:
        changed = False
        for addr, current_aliases in list(aliases.items()):
            new_aliases = set(current_aliases)
            for alias in current_aliases:
                if alias in aliases:
                    new_aliases.update(aliases[alias])
            if new_aliases != current_aliases:
                aliases[addr] = new_aliases
                changed = True

    return aliases


__all__ = ["compute_transitive_aliases", "extract_lea_target"]
