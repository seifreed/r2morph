"""Detection helpers for switch table analysis."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger(__name__)


def is_plt_stub_pattern(data: bytes) -> bool:
    """Check if bytes match common PLT stub patterns."""
    if len(data) < 6:
        return False

    if data[:2] == b"\xff\x25":
        return True

    if data[:2] == b"\xff\x27":
        return True

    if len(data) >= 10 and data[:6] == b"\xff\x35" and data[6:10] == b"\x48\x8d\x3d":
        return True

    if data[:6] == b"\x48\x8b\x1d" or data[:6] == b"\x48\x8b\x05":
        return True

    return False


def detect_tail_calls(
    binary: Any,
    known_functions: Mapping[int, str] | None,
    function_address: int,
) -> list[tuple[int, int]]:
    """Detect tail calls in a function."""
    tail_calls: list[tuple[int, int]] = []

    if not known_functions:
        return tail_calls

    try:
        instructions = binary.get_function_disasm(function_address)
    except Exception as exc:
        logger.debug(f"Failed to get disassembly: {exc}")
        return tail_calls

    for insn in instructions:
        addr = insn.get("offset", 0)
        mnemonic = insn.get("type", "").lower()
        disasm = insn.get("opcode", insn.get("disasm", ""))

        if mnemonic != "jmp":
            continue

        match = re.search(r"jmp\s+(0x[0-9a-f]+)", disasm, re.IGNORECASE)
        if not match:
            continue

        try:
            target = int(match.group(1), 16)
        except ValueError:
            continue

        if target in known_functions:
            tail_calls.append((addr, target))
            logger.debug(f"Tail call at 0x{addr:x} -> 0x{target:x} ({known_functions[target]})")

    return tail_calls


def detect_plt_got_thunks(binary: Any) -> dict[int, dict[str, Any]]:
    """Detect PLT/GOT thunk entries."""
    plt_entries: dict[int, dict[str, Any]] = {}

    try:
        sections = binary.get_sections()
    except Exception:
        sections = []

    plt_sections = [s for s in sections if "plt" in s.get("name", "").lower() or ".plt" in s.get("name", "").lower()]

    if not plt_sections:
        logger.debug("No PLT section found")
        return plt_entries

    for section in plt_sections:
        start = section.get("addr", section.get("virtual_address", 0))
        size = section.get("size", section.get("virtual_size", 0))

        if start == 0 or size == 0:
            continue

        try:
            data = binary.read_bytes(start, min(size, 0x1000))
        except Exception:
            continue

        if not data:
            continue

        offset = 0
        while offset < len(data) - 16:
            chunk = data[offset : offset + 16]

            if is_plt_stub_pattern(chunk):
                thunk_addr = start + offset
                plt_entries[thunk_addr] = {
                    "address": thunk_addr,
                    "section": section.get("name", ""),
                    "type": "plt_stub",
                }
                offset += 16
            else:
                offset += 1

    logger.debug(f"Found {len(plt_entries)} PLT entries")
    return plt_entries
