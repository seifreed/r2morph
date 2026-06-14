"""Validation helpers for binary integrity checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def detect_binary_format(binary_path: Path) -> str:
    """Detect the binary format from the file magic."""
    try:
        with open(binary_path, "rb") as f:
            magic = f.read(4)

        if magic[:2] == b"MZ":
            return "pe"

        if magic in (b"\x7fELF", b"\x7f\x45\x4c\x46"):
            return "elf"

        if magic in (
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
        ):
            return "macho"

        if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            return "fat_macho"

        return "unknown"
    except Exception:
        return "unknown"


def validate_elf_integrity(handler: Any) -> tuple[bool, list[str]]:
    """Validate ELF binary integrity."""
    issues: list[str] = []

    try:
        if not handler.is_elf():
            issues.append("Not a valid ELF binary")
            return False, issues

        sections = handler.get_sections()
        if not sections:
            issues.append("No sections found in ELF")

        segments = handler.get_segments()
        if not segments:
            issues.append("No segments found in ELF")

        section_names = {s.get("name", "") for s in sections}

        required_sections = [".text", ".data"]
        for req in required_sections:
            if req not in section_names:
                issues.append(f"Missing required section: {req}")

        for segment in segments:
            flags = segment.get("flags", 0)
            p_flags_executable = 0x1
            p_flags_writable = 0x2

            if flags & p_flags_executable and flags & p_flags_writable:
                issues.append(f"Segment at 0x{segment.get('virtual_address', 0):x} is both writable and executable")

        entry_point = handler.get_entry_point()
        if entry_point is not None:
            found_entry = False
            for seg in segments:
                va = seg.get("virtual_address", 0)
                size = seg.get("virtual_size", seg.get("memsz", 0))
                if va <= entry_point < va + size:
                    found_entry = True
                    break
            if not found_entry:
                issues.append(f"Entry point 0x{entry_point:x} not in any executable segment")

    except Exception as e:
        issues.append(f"ELF validation error: {e}")

    return len(issues) == 0, issues


def validate_macho_integrity(handler: Any) -> tuple[bool, list[str]]:
    """Validate Mach-O binary integrity."""
    issues: list[str] = []

    try:
        if not handler.is_macho():
            issues.append("Not a valid Mach-O binary")
            return False, issues

        ok, msg = handler.validate_integrity()
        if not ok:
            issues.append(f"Mach-O integrity issue: {msg}")

        segments = handler.get_segments()
        if not segments:
            issues.append("No segments found in Mach-O")

        load_commands = handler.get_load_commands()
        if not load_commands:
            issues.append("No load commands found")

        has_text = False
        has_linkedit = False
        for seg in segments:
            name = seg.get("name", "")
            if name == "__TEXT":
                has_text = True
            elif name == "__LINKEDIT":
                has_linkedit = True

        if not has_text:
            issues.append("Missing __TEXT segment")
        if not has_linkedit:
            issues.append("Missing __LINKEDIT segment")

        for seg in segments:
            for other in segments:
                if seg is other:
                    continue
                va1 = seg.get("virtual_address", 0)
                size1 = seg.get("virtual_size", 0)
                va2 = other.get("virtual_address", 0)
                size2 = other.get("virtual_size", 0)

                if va1 < va2 + size2 and va1 + size1 > va2:
                    issues.append(f"Overlapping segments: {seg.get('name')} and {other.get('name')}")

    except Exception as e:
        issues.append(f"Mach-O validation error: {e}")

    return len(issues) == 0, issues


def validate_pe_integrity(handler: Any) -> tuple[bool, list[str]]:
    """Validate PE binary integrity."""
    return handler.validate_integrity()
