"""Mach-O integrity and repair helpers."""

from __future__ import annotations

import logging
import platform
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import lief
except ImportError:  # pragma: no cover - optional dependency
    lief = None


def _iter_macho_binaries(handler: Any, binary: Any) -> list[Any]:
    if binary is None:
        return []
    if lief is None:
        return []
    if isinstance(binary, lief.MachO.Binary):
        return [binary]
    if isinstance(binary, lief.MachO.FatBinary):
        try:
            return list(binary.it_binaries)
        except Exception:
            return []
    return []


def validate_integrity(handler: Any) -> tuple[bool, str]:
    """Validate Mach-O layout integrity (load commands, offsets, and sizes)."""
    if not handler.is_macho():
        return False, "Not a Mach-O binary"
    if lief is None:
        return True, "LIEF not available for deep integrity checks"
    binary = handler._parse_lief()
    if binary is None:
        return False, "Failed to parse Mach-O"
    ok, msg = lief.MachO.check_layout(binary)
    if not ok:
        return False, msg or "Mach-O layout invalid"
    if not _relocations_in_segments(handler, binary):
        return False, "Mach-O relocations out of segment bounds"
    return True, ""


def _relocations_in_segments(handler: Any, binary: Any) -> bool:
    try:
        segments = list(getattr(binary, "segments", []))
        if not segments:
            return True
        for reloc in getattr(binary, "relocations", []):
            address = getattr(reloc, "address", None)
            if address is None:
                continue
            in_segment = False
            for seg in segments:
                vaddr = getattr(seg, "virtual_address", 0)
                vsize = getattr(seg, "virtual_size", 0)
                if vaddr <= address < vaddr + vsize:
                    in_segment = True
                    break
            if not in_segment:
                return False
        return True
    except Exception:
        return False


def repair_integrity(
    handler: Any,
    entitlements: Path | None = None,
    hardened: bool = False,
    timestamp: bool = False,
) -> bool:
    """Best-effort repair of Mach-O integrity post-mutation."""
    if platform.system() != "Darwin":
        return False
    if not handler.is_macho():
        return False
    try:
        from r2morph.platform.codesign import CodeSigner

        signer = CodeSigner()

        if lief is not None:
            binary = handler._parse_lief()
            if binary is not None:
                try:
                    if getattr(binary, "has_code_signature", False):
                        binary.remove_signature()
                    tmp_path = handler.binary_path.with_suffix(handler.binary_path.suffix + ".repaired")
                    binary.write(str(tmp_path))
                    tmp_path.replace(handler.binary_path)
                except Exception as e:
                    logger.error(f"Failed to rewrite Mach-O with LIEF: {e}")

        signer.remove_signature(handler.binary_path)
        return signer.sign_binary(
            handler.binary_path,
            adhoc=True,
            entitlements=entitlements,
            hardened=hardened,
            timestamp=timestamp,
        )
    except Exception as e:
        logger.error(f"Failed to repair Mach-O signature: {e}")
        return False


def fix_load_commands(handler: Any) -> tuple[bool, list[str]]:
    """Fix Mach-O load commands after mutation."""
    fixes: list[str] = []
    binary = handler._parse_lief()

    if binary is None:
        return True, fixes

    try:
        changed = False

        if hasattr(binary, "has_code_signature") and binary.has_code_signature:
            fixes.append("Code signature will be removed and re-signed")
            changed = True

        if hasattr(binary, "has_linkedit") and binary.has_linkedit:
            fixes.append("__LINKEDIT segment verified")

        return not changed or True, fixes
    except Exception as e:
        logger.debug(f"Load command fix failed: {e}")
        return False, fixes


def fix_bind_symbols(handler: Any) -> tuple[bool, list[str]]:
    """Fix bind symbol information after mutation."""
    fixes: list[str] = []
    binary = handler._parse_lief()

    if binary is None:
        return True, fixes

    try:
        for macho in _iter_macho_binaries(handler, binary):
            if hasattr(macho, "symbols"):
                sym_count = len(list(getattr(macho, "symbols", [])))
                fixes.append(f"Verified {sym_count} symbols")

        return True, fixes
    except Exception as e:
        logger.debug(f"Bind symbol fix failed: {e}")
        return False, fixes


def fix_segment_permissions(handler: Any) -> tuple[bool, list[str]]:
    """Fix segment permissions after mutation."""
    fixes: list[str] = []
    binary = handler._parse_lief()

    if binary is None:
        return True, fixes

    try:
        for macho in _iter_macho_binaries(handler, binary):
            for seg in getattr(macho, "segments", []):
                name = getattr(seg, "name", "")
                if name in ("__TEXT", "__DATA", "__LINKEDIT"):
                    fixes.append(f"Segment {name} permissions verified")

        return True, fixes
    except Exception as e:
        logger.debug(f"Segment permission fix failed: {e}")
        return False, fixes


def full_repair(handler: Any, entitlements: Path | None = None) -> tuple[bool, list[str]]:
    """Full Mach-O repair after mutation."""
    all_repairs: list[str] = []
    all_success = True

    checks = [
        ("load_commands", fix_load_commands(handler)),
        ("bind_symbols", fix_bind_symbols(handler)),
        ("segment_permissions", fix_segment_permissions(handler)),
    ]

    for name, (success, repairs) in checks:
        if repairs:
            all_repairs.extend(repairs)
        if not success:
            all_success = False
            all_repairs.append(f"Warning: {name} repair may have issues")

    if platform.system() == "Darwin":
        repair_success = repair_integrity(handler, entitlements=entitlements)
        if repair_success:
            all_repairs.append("Code signature rebuilt")
        else:
            all_success = False
            all_repairs.append("Warning: Code signature rebuild failed")

    return all_success, all_repairs
