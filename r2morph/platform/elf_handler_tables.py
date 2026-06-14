"""Projection helpers for ELF handlers."""

from __future__ import annotations

import logging
from typing import Any, BinaryIO

from r2morph.platform.elf_structs import (
    MAX_SECTION_ENTRY_SIZE,
    MAX_SECTIONS,
    _build_section_dict,
    _build_segment_dict,
    _parse_program_header_entry,
    _parse_section_header_entry,
)

logger = logging.getLogger(__name__)


def collect_sections(binary_path: Any, header: dict[str, Any], file_obj: BinaryIO) -> list[dict[str, Any]]:
    """Materialize ELF sections from a parsed header and file handle."""
    from r2morph.platform.elf_handler_parsing import get_section_name, read_shstrtab

    try:
        is_64bit = header["is_64bit"]
        endian = "<" if header["is_little_endian"] else ">"

        file_size = binary_path.stat().st_size
        shstrtab_data = read_shstrtab(file_obj, header, file_size)

        sections = []
        file_obj.seek(header["e_shoff"])

        section_count = min(header["e_shnum"], MAX_SECTIONS)
        section_entry_size = min(header["e_shentsize"], MAX_SECTION_ENTRY_SIZE)

        if header["e_shnum"] > MAX_SECTIONS:
            logger.warning(f"Excessive section count {header['e_shnum']}, limiting to {MAX_SECTIONS}")
        if header["e_shentsize"] > MAX_SECTION_ENTRY_SIZE:
            logger.warning(
                f"Excessive section entry size {header['e_shentsize']}, limiting to {MAX_SECTION_ENTRY_SIZE}"
            )

        for i in range(section_count):
            sh_data = file_obj.read(section_entry_size)
            if len(sh_data) < section_entry_size:
                logger.warning(f"Truncated section header at index {i}")
                break

            entry = _parse_section_header_entry(sh_data, is_64bit, endian)
            section_name = get_section_name(entry["sh_name"], shstrtab_data)
            sections.append(_build_section_dict(entry, section_name, i))

        logger.debug(f"Parsed {len(sections)} sections from {binary_path}")
        return sections
    except Exception as exc:
        logger.error(f"Failed to collect sections: {exc}")
        return []


def collect_segments(binary_path: Any, header: dict[str, Any], file_obj: BinaryIO) -> list[dict[str, Any]]:
    """Materialize ELF segments from a parsed header and file handle."""
    try:
        is_64bit = header["is_64bit"]
        endian = "<" if header["is_little_endian"] else ">"

        segments = []
        file_obj.seek(header["e_phoff"])

        for i in range(header["e_phnum"]):
            ph_data = file_obj.read(header["e_phentsize"])
            if len(ph_data) < header["e_phentsize"]:
                logger.warning(f"Truncated program header at index {i}")
                break

            entry = _parse_program_header_entry(ph_data, is_64bit, endian)
            segments.append(_build_segment_dict(entry, i))

        logger.debug(f"Parsed {len(segments)} segments from {binary_path}")
        return segments
    except Exception as exc:
        logger.error(f"Failed to collect segments: {exc}")
        return []


__all__ = ["collect_sections", "collect_segments"]
