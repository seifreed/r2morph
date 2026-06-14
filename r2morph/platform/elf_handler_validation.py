"""Validation helpers for ELF handlers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from r2morph.platform.elf_structs import _header_table_within_file

logger = logging.getLogger(__name__)


def validate_elf_file_structure(binary_path: Path, header: dict[str, Any]) -> bool:
    """Validate ELF section/program header tables against file bounds."""
    file_size = binary_path.stat().st_size

    sh_size = header["e_shentsize"] * header["e_shnum"]
    if not _header_table_within_file(header["e_shoff"], sh_size, file_size, "Section header table"):
        return False

    ph_size = header["e_phentsize"] * header["e_phnum"]
    if not _header_table_within_file(header["e_phoff"], ph_size, file_size, "Program header table"):
        return False

    logger.debug(f"ELF validation passed for: {binary_path}")
    return True


__all__ = ["validate_elf_file_structure"]
