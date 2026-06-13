"""Memory-write signature helpers for real-binary region comparison."""

from __future__ import annotations

from typing import Any


def collect_memory_write_signatures(state: Any) -> list[str]:
    """Collect a compact, best-effort signature of memory writes from an angr state."""
    signatures: list[str] = []
    history = getattr(state, "history", None)
    actions = getattr(history, "actions", None)
    if not actions:
        return signatures

    for action in actions:
        action_type = getattr(action, "type", "")
        action_action = getattr(action, "action", "")
        if action_type != "mem" or action_action not in {"write", "store"}:
            continue

        addr = getattr(action, "addr", None)
        size = getattr(action, "size", None)
        try:
            raw_addr = getattr(addr, "concrete_value", addr)
            addr_value = int(raw_addr) if raw_addr is not None else None
        except (TypeError, ValueError):
            addr_value = None
        try:
            raw_size = getattr(size, "concrete_value", size)
            size_value = int(raw_size) if raw_size is not None else None
        except (TypeError, ValueError):
            size_value = None

        if addr_value is None:
            signatures.append("unknown")
        elif size_value is None:
            signatures.append(f"0x{addr_value:x}")
        else:
            signatures.append(f"0x{addr_value:x}:{size_value}")

    return sorted(set(signatures))
