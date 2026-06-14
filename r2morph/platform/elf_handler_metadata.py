"""Metadata projection helpers for ELF handlers."""

from __future__ import annotations

from typing import Any

MACHINE_NAMES = {
    0x03: "x86",
    0x3E: "x86_64",
    0x28: "ARM",
    0xB7: "AArch64",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0xF3: "RISC-V",
}


def get_entry_point(header: dict[str, Any] | None) -> int | None:
    """Return the parsed ELF entry point."""
    if header is None:
        return None
    entry = header.get("e_entry")
    return int(entry) if entry is not None else None


def get_architecture(header: dict[str, Any] | None) -> dict[str, Any]:
    """Return a normalized ELF architecture description."""
    if header is None:
        return {}

    machine = header.get("e_machine", 0)
    return {
        "machine": machine,
        "machine_name": MACHINE_NAMES.get(machine, f"Unknown({machine})"),
        "bits": 64 if header.get("is_64bit") else 32,
        "endian": "little" if header.get("is_little_endian") else "big",
    }


__all__ = ["get_architecture", "get_entry_point"]
