"""Parsing helpers for ELF handlers."""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import Any, BinaryIO

from r2morph.platform.elf_structs import (
    ELF_MAGIC,
    ELFCLASS64,
    ELFDATA2LSB,
    MAX_SECTION_NAME,
    _build_elf_header_dict,
)

logger = logging.getLogger(__name__)


def parse_elf_header(binary_path: Path) -> tuple[dict[str, Any] | None, bool | None, bool | None]:
    """Parse and return the ELF header plus cached class/endian flags."""
    try:
        with open(binary_path, "rb") as f:
            e_ident = f.read(16)
            if len(e_ident) < 16 or e_ident[:4] != ELF_MAGIC:
                logger.error("Invalid ELF magic number")
                return None, None, None

            is_64bit = e_ident[4] == ELFCLASS64
            is_little_endian = e_ident[5] == ELFDATA2LSB

            endian = "<" if is_little_endian else ">"
            offset_fields = "QQQ" if is_64bit else "III"
            fmt = f"{endian}HHI {offset_fields} IHHHHHH"

            data = f.read(struct.calcsize(fmt))
            if len(data) < struct.calcsize(fmt):
                logger.error("Truncated ELF header")
                return None, is_64bit, is_little_endian

            header = _build_elf_header_dict(
                e_ident,
                struct.unpack(fmt, data),
                is_64bit=is_64bit,
                is_little_endian=is_little_endian,
            )
            return header, is_64bit, is_little_endian
    except Exception as exc:
        logger.error(f"Failed to parse ELF header: {exc}")
        return None, None, None


def get_section_name(name_offset: int, shstrtab_data: bytes) -> str:
    """Extract a section name from the ELF section string table."""
    if name_offset >= len(shstrtab_data):
        return ""

    end = shstrtab_data.find(b"\x00", name_offset)
    if end == -1:
        end = len(shstrtab_data)

    if end - name_offset > MAX_SECTION_NAME:
        end = name_offset + MAX_SECTION_NAME

    return shstrtab_data[name_offset:end].decode("utf-8", errors="replace")


def read_shstrtab(f: BinaryIO, header: dict[str, Any], file_size: int) -> bytes:
    """Read the section header string table bytes, or b'' if unavailable."""
    if header["e_shstrndx"] >= header["e_shnum"]:
        return b""

    endian = "<" if header["is_little_endian"] else ">"
    shstrtab_offset = header["e_shoff"] + header["e_shstrndx"] * header["e_shentsize"]
    if shstrtab_offset > file_size or shstrtab_offset < header["e_shoff"]:
        logger.warning(f"Invalid shstrtab offset: {shstrtab_offset}")
        return b""

    f.seek(shstrtab_offset)
    shstrtab_header = f.read(header["e_shentsize"])
    if len(shstrtab_header) < header["e_shentsize"]:
        logger.warning("Truncated shstrtab header")
        return b""

    if header["is_64bit"]:
        sh_offset = struct.unpack(f"{endian}Q", shstrtab_header[24:32])[0]
        sh_size = struct.unpack(f"{endian}Q", shstrtab_header[32:40])[0]
    else:
        sh_offset = struct.unpack(f"{endian}I", shstrtab_header[16:20])[0]
        sh_size = struct.unpack(f"{endian}I", shstrtab_header[20:24])[0]

    if sh_offset + sh_size > file_size:
        logger.warning(f"shstrtab extends beyond file: offset={sh_offset}, size={sh_size}")
        return b""

    f.seek(sh_offset)
    return f.read(sh_size)


__all__ = ["get_section_name", "parse_elf_header", "read_shstrtab"]
