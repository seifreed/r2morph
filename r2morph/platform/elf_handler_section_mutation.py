"""Section mutation helpers for ELF handlers."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def add_section(binary_path: Path, name: str, size: int, flags: int = 0x6) -> int | None:
    """Add a new ELF section using LIEF."""
    try:
        import lief
    except ImportError:
        logger.error("lief library required for section manipulation. Install with: pip install lief")
        return None

    try:
        elf = lief.parse(str(binary_path))
        if elf is None:
            logger.error(f"Failed to parse ELF with lief: {binary_path}")
            return None

        if not isinstance(elf, lief.ELF.Binary):
            logger.error("Parsed binary is not ELF format")
            return None

        existing = elf.get_section(name)
        if existing is not None:
            logger.warning(f"Section '{name}' already exists at 0x{existing.virtual_address:x}")
            return existing.virtual_address

        section = lief.ELF.Section(name)
        section.type = lief.ELF.Section.TYPE.PROGBITS
        section.flags = lief.ELF.Section.FLAGS(flags)
        section.content = list(bytes(size))
        section.alignment = 0x10

        added_section = elf.add(section, loaded=True)
        if added_section is None:
            logger.error(f"Failed to add section '{name}' to ELF")
            return None

        elf.write(str(binary_path))
        vaddr = added_section.virtual_address
        logger.info(f"Added ELF section '{name}' ({size} bytes, flags=0x{flags:x}) at vaddr 0x{vaddr:x}")
        return vaddr
    except Exception as exc:
        logger.error(f"Failed to add section '{name}': {exc}")
        return None


__all__ = ["add_section"]
