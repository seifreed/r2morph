"""Format-specific repair helpers for binary integrity validation."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def repair_elf_integrity(handler: Any) -> tuple[bool, list[str]]:
    """Repair ELF binary integrity."""
    repairs: list[str] = []

    try:
        if hasattr(handler, "fix_section_headers") and handler.fix_section_headers():
            repairs.append("Fixed section headers")

        if hasattr(handler, "fix_program_headers") and handler.fix_program_headers():
            repairs.append("Fixed program headers")

        logger.info("ELF repairs: %s", repairs)
        return True, repairs
    except Exception as e:
        logger.error("ELF repair error: %s", e)
        repairs.append(f"Error: {e}")
        return False, repairs


def repair_macho_integrity(handler: Any) -> tuple[bool, list[str]]:
    """Repair Mach-O binary integrity."""
    repairs: list[str] = []

    try:
        if hasattr(handler, "repair_integrity"):
            success = handler.repair_integrity()
            if success:
                repairs.append("Repaired Mach-O signature")
            else:
                repairs.append("Signature repair attempted")

        if hasattr(handler, "mark_executable"):
            try:
                handler.mark_executable()
                repairs.append("Marked executable")
            except (OSError, ValueError, RuntimeError) as exc:
                logger.warning("mark_executable() failed during Mach-O repair: %s", exc)
                repairs.append(f"Failed to mark executable: {exc}")

        logger.info("Mach-O repairs: %s", repairs)
        return True, repairs
    except Exception as e:
        logger.error("Mach-O repair error: %s", e)
        repairs.append(f"Error: {e}")
        return False, repairs


def repair_pe_integrity(handler: Any) -> tuple[bool, list[str]]:
    """Repair PE binary integrity."""
    repairs: list[str] = []

    try:
        success, repairs_made = handler.repair_integrity()
        repairs.extend(repairs_made)

        if hasattr(handler, "refresh_headers"):
            handler.refresh_headers()
            repairs.append("Refreshed PE headers")

        logger.info("PE repairs: %s", repairs)
        return success, repairs
    except Exception as e:
        logger.error("PE repair error: %s", e)
        repairs.append(f"Error: {e}")
        return False, repairs
