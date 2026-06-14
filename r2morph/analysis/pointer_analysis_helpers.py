"""Pure helpers for pointer alias analysis."""

from __future__ import annotations


def extract_lea_target(disasm: str) -> int | None:
    """Extract LEA target from disassembly."""
    parts = disasm.split("[")
    if len(parts) < 2:
        return None

    bracket_content = parts[1].split("]")[0]
    if bracket_content.startswith("0x"):
        try:
            return int(bracket_content, 16)
        except ValueError:
            # Not a parseable numeric literal here (e.g. register/symbolic operand); expected, so this candidate is skipped.
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


__all__ = ["extract_lea_target", "compute_transitive_aliases"]
