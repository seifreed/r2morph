"""Section mutation helpers for ELF handlers."""

from __future__ import annotations

import logging
from importlib import import_module
from pathlib import Path

logger = logging.getLogger(__name__)


def add_section(binary_path: Path, name: str, size: int, flags: int = 0x6) -> int | None:
    """Add a new ELF section using LIEF."""
    virtual_address = None
    try:
        lief = import_module("lief")
    except ImportError:
        logger.error("lief library required for section manipulation. Install with: pip install lief")
    else:
        try:
            elf = lief.parse(str(binary_path))
            if elf is None:
                logger.error(f"Failed to parse ELF with lief: {binary_path}")
            elif not isinstance(elf, lief.ELF.Binary):
                logger.error("Parsed binary is not ELF format")
            else:
                existing = elf.get_section(name)
                if existing is not None:
                    virtual_address = int(existing.virtual_address)
                    logger.warning(f"Section '{name}' already exists at 0x{virtual_address:x}")
                else:
                    section = lief.ELF.Section(name)
                    section.type = lief.ELF.Section.TYPE.PROGBITS
                    section.flags = flags
                    section.content = list(bytes(size))
                    section.alignment = 0x10
                    added_section = elf.add(section, loaded=True)
                    if added_section is None:
                        logger.error(f"Failed to add section '{name}' to ELF")
                    else:
                        elf.write(str(binary_path))
                        virtual_address = int(added_section.virtual_address)
                        logger.info(
                            f"Added ELF section '{name}' ({size} bytes, flags=0x{flags:x}) "
                            f"at vaddr 0x{virtual_address:x}"
                        )
        except Exception as exc:
            logger.error(f"Failed to add section '{name}': {exc}")
    return virtual_address


__all__ = ["add_section"]
