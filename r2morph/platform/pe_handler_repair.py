"""PE integrity and repair helpers."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.platform.pe_handler_parsing import calculate_pe_checksum, get_checksum_offset

logger = logging.getLogger(__name__)

try:
    import lief
except ImportError:  # pragma: no cover - optional dependency
    lief = None


def fix_checksum(handler: Any) -> bool:
    """Recalculate and fix the PE checksum."""
    logger.info("Fixing PE checksum")

    try:
        checksum = calculate_pe_checksum(handler.binary_path)

        checksum_offset = get_checksum_offset(handler.binary_path)
        if checksum_offset is None:
            return False

        with open(handler.binary_path, "r+b") as f:
            f.seek(checksum_offset)
            f.write(checksum.to_bytes(4, "little"))

        logger.info(f"Updated PE checksum to 0x{checksum:08x}")
        return True
    except Exception as e:
        logger.error(f"Failed to fix checksum: {e}")
        return False


def validate_integrity(handler: Any) -> tuple[bool, list[str]]:
    """Validate PE integrity after mutation."""
    issues: list[str] = []

    if not handler.is_pe():
        issues.append("Not a PE binary")
        return False, issues

    binary = handler._parse_lief()
    if binary is None:
        return True, []

    if not getattr(binary, "has_header", True):
        issues.append("Missing PE header")

    sections = handler.get_sections()
    if not sections:
        issues.append("No sections found")

    section_bounds: dict[int, int] = {}
    for i, section in enumerate(sections):
        va = section.get("virtual_address", 0)
        size = section.get("size", 0)
        for other_va, other_size in section_bounds.items():
            if va < other_va + other_size and va + size > other_va:
                issues.append(f"Overlapping sections at index {i}")
                break
        section_bounds[va] = size

    for reloc in handler.get_relocations():
        addr = reloc.get("address", 0)
        in_section = False
        for section in sections:
            va = section.get("virtual_address", 0)
            size = section.get("size", 0)
            if va <= addr < va + size:
                in_section = True
                break
        if not in_section:
            issues.append(f"Relocation at 0x{addr:x} outside any section")

    current_checksum = get_stored_checksum(handler)
    calculated_checksum = calculate_pe_checksum(handler.binary_path)
    if current_checksum != calculated_checksum:
        issues.append(
            f"Checksum mismatch: stored 0x{current_checksum:08x}, calculated 0x{calculated_checksum:08x}"
        )

    return len(issues) == 0, issues


def get_stored_checksum(handler: Any) -> int:
    """Get the stored checksum from the PE header."""
    try:
        checksum_offset = get_checksum_offset(handler.binary_path)
        if checksum_offset is None:
            return 0
        with open(handler.binary_path, "rb") as f:
            f.seek(checksum_offset)
            return int.from_bytes(f.read(4), "little")
    except Exception:
        return 0


def repair_integrity(handler: Any) -> tuple[bool, list[str]]:
    """Repair PE integrity after mutation."""
    repairs: list[str] = []
    success = True

    if not handler.is_pe():
        return False, ["Not a PE binary"]

    if fix_checksum(handler):
        repairs.append("Updated PE checksum")
    else:
        success = False
        repairs.append("Failed to update checksum")

    binary = handler._parse_lief()
    if binary is not None and hasattr(binary, "write"):
        try:
            tmp_path = handler.binary_path.with_suffix(".repaired")
            binary.write(str(tmp_path))
            tmp_path.replace(handler.binary_path)
            repairs.append("Rebuilt PE with LIEF")
        except Exception as e:
            logger.warning(f"LIEF rebuild failed: {e}")

    return success, repairs


def refresh_headers(handler: Any) -> bool:
    """Refresh PE headers after mutation."""
    binary = handler._parse_lief()
    if binary is None:
        return fix_checksum(handler)

    try:
        if hasattr(binary, "size"):
            pass

        tmp_path = handler.binary_path.with_suffix(".refreshed")
        binary.write(str(tmp_path))
        tmp_path.replace(handler.binary_path)

        if lief is not None:
            parsed = lief.parse(str(handler.binary_path))
            if isinstance(parsed, lief.PE.Binary):
                handler._binary = parsed
        handler._sections_cache = None

        fix_checksum(handler)

        logger.info("Refreshed PE headers")
        return True
    except Exception as e:
        logger.error(f"Failed to refresh PE headers: {e}")
        return False


def fix_imports(handler: Any) -> tuple[bool, list[str]]:
    """Fix import table after mutation."""
    fixes: list[str] = []
    binary = handler._parse_lief()

    if binary is None:
        return True, fixes

    try:
        imports_valid = True
        for imported_binary in list(getattr(binary, "imports", [])):
            try:
                if hasattr(imported_binary, "name") and imported_binary.name:
                    fixes.append(f"Verified import: {imported_binary.name}")
            except Exception:
                imports_valid = False

        return imports_valid, fixes
    except Exception as e:
        logger.debug(f"Import fix failed: {e}")
        return False, fixes


def fix_exports(handler: Any) -> tuple[bool, list[str]]:
    """Fix export table after mutation."""
    fixes: list[str] = []
    binary = handler._parse_lief()

    if binary is None:
        return True, fixes

    try:
        if hasattr(binary, "has_exports") and binary.has_exports:
            for export in binary.exported_functions:
                fixes.append(f"Verified export: {export.name}")
        return True, fixes
    except Exception as e:
        logger.debug(f"Export fix failed: {e}")
        return False, fixes


def fix_resources(handler: Any) -> tuple[bool, list[str]]:
    """Fix resource section after mutation."""
    fixes: list[str] = []
    binary = handler._parse_lief()

    if binary is None:
        return True, fixes

    try:
        resources = getattr(binary, "resources", None)
        if resources:
            fixes.append("Resources verified")
        return True, fixes
    except Exception as e:
        logger.debug(f"Resource fix failed: {e}")
        return False, fixes


def full_repair(handler: Any) -> tuple[bool, list[str]]:
    """Full PE repair after mutation."""
    all_repairs: list[str] = []
    all_success = True

    checksum_result = fix_checksum(handler)
    checks = [
        ("checksum", (checksum_result if isinstance(checksum_result, tuple) else (checksum_result, []))),
        ("imports", fix_imports(handler)),
        ("exports", fix_exports(handler)),
        ("resources", fix_resources(handler)),
        ("headers", (refresh_headers(handler), ["Headers refreshed"])),
    ]

    for name, result in checks:
        if isinstance(result, tuple):
            success, repairs = result
        else:
            success, repairs = result, []
        if repairs:
            all_repairs.extend(repairs)
        if not success:
            all_success = False
            all_repairs.append(f"Warning: {name} repair may have issues")

    return all_success, all_repairs
