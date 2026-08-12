"""Mach-O thin-slice resolution for native and fat binaries."""

from __future__ import annotations

import logging
import struct
from typing import BinaryIO

logger = logging.getLogger(__name__)

MAGIC_SIZE_BYTES = 4
MACHO_MAGICS_64 = {0xFEEDFACF, 0xCFFAEDFE}

_MACHO_MAGICS_NATIVE_LE = {0xFEEDFACE, 0xFEEDFACF}
_MACHO_MAGICS_NATIVE_BE = {0xCEFAEDFE, 0xCFFAEDFE}
_FAT_MAGICS_BE = {0xCAFEBABE, 0xCAFEBABF, 0xBEBAFECA, 0xBFBAFECA}
_FAT_ARCH_LAYOUTS = {
    0xCAFEBABE: ("IIIII", 20),
    0xCAFEBABF: ("IIQQII", 32),
}
_MAX_FAT_ARCHITECTURES = 100


def resolve_macho_arch(stream: BinaryIO, file_size: int) -> tuple[str, int, int] | None:
    """Return ``(endian, offset, magic)`` for a thin Mach-O image."""
    magic_bytes = stream.read(MAGIC_SIZE_BYTES)
    if len(magic_bytes) != MAGIC_SIZE_BYTES:
        return None

    little_magic, big_magic = _unpack_magics(magic_bytes)
    if big_magic in _FAT_MAGICS_BE:
        return _resolve_fat_arch(stream, file_size, big_magic)
    return _resolve_thin_arch(little_magic, big_magic, 0)


def _resolve_fat_arch(
    stream: BinaryIO,
    file_size: int,
    big_magic: int,
) -> tuple[str, int, int] | None:
    endian = ">" if big_magic in {0xCAFEBABE, 0xCAFEBABF} else "<"
    stream.seek(0)
    header_magic = _read_uint32(stream, endian)
    if header_magic is None:
        return None

    offset = _read_fat_arch_offset(stream, file_size, endian, header_magic)
    if offset is None:
        return None

    stream.seek(offset)
    magic_bytes = stream.read(MAGIC_SIZE_BYTES)
    if len(magic_bytes) != MAGIC_SIZE_BYTES:
        return None
    little_magic, thin_big_magic = _unpack_magics(magic_bytes)
    return _resolve_thin_arch(little_magic, thin_big_magic, offset)


def _read_fat_arch_offset(
    stream: BinaryIO,
    file_size: int,
    endian: str,
    header_magic: int,
) -> int | None:
    architecture_count = _read_uint32(stream, endian)
    if architecture_count is None:
        return None
    if not 1 <= architecture_count <= _MAX_FAT_ARCHITECTURES:
        logger.warning("Invalid nfat count: %d", architecture_count)
        return None

    layout = _FAT_ARCH_LAYOUTS.get(header_magic)
    if layout is None:
        return None
    field_format, record_size = layout
    architecture_data = stream.read(record_size)
    if len(architecture_data) != record_size:
        return None

    architecture_offset = int(struct.unpack(endian + field_format, architecture_data)[2])
    if architecture_offset >= file_size:
        logger.warning(
            "Invalid arch_offset 0x%x exceeds file size 0x%x",
            architecture_offset,
            file_size,
        )
        return None
    return architecture_offset


def _read_uint32(stream: BinaryIO, endian: str) -> int | None:
    value = stream.read(MAGIC_SIZE_BYTES)
    if len(value) != MAGIC_SIZE_BYTES:
        return None
    return int(struct.unpack(endian + "I", value)[0])


def _unpack_magics(magic_bytes: bytes) -> tuple[int, int]:
    return struct.unpack("<I", magic_bytes)[0], struct.unpack(">I", magic_bytes)[0]


def _resolve_thin_arch(
    little_magic: int,
    big_magic: int,
    offset: int,
) -> tuple[str, int, int] | None:
    if little_magic in _MACHO_MAGICS_NATIVE_LE:
        return "<", offset, little_magic
    if little_magic in _MACHO_MAGICS_NATIVE_BE:
        return ">", offset, big_magic
    return None
