"""Code-cave search helpers for ELF handlers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from r2morph.platform.elf_structs import SHF_EXECINSTR, _find_null_run

logger = logging.getLogger(__name__)


def find_code_cave(binary_path: Path, sections: list[dict[str, Any]], min_size: int = 64) -> int | None:
    """Find a code cave (unused space) inside executable ELF sections."""
    try:
        with open(binary_path, "rb") as f:
            for section in sections:
                if not (section["flags"] & SHF_EXECINSTR):
                    continue
                if section["size"] < min_size:
                    continue

                f.seek(section["offset"])
                data = f.read(section["size"])

                null_start = _find_null_run(data, min_size)
                if null_start is not None:
                    vaddr = section["vaddr"] + null_start
                    logger.info(f"Found code cave: {min_size} bytes at 0x{vaddr:x} in {section['name']}")
                    return int(vaddr)

        logger.debug(f"No code cave of {min_size}+ bytes found")
        return None
    except Exception as exc:
        logger.error(f"Failed to find code cave: {exc}")
        return None


__all__ = ["find_code_cave"]
