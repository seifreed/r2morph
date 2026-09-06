"""Mach-O compact unwind metadata parsing."""

from __future__ import annotations

import logging
import struct
from dataclasses import replace
from typing import Any

from r2morph.analysis.exception_models import ExceptionFrame

logger = logging.getLogger(__name__)

_HEADER_SIZE_BYTES = 16
_INDEX_ENTRY_SIZE_BYTES = 12
_REGULAR_PAGE_HEADER_SIZE_BYTES = 8
_COMPRESSED_PAGE_HEADER_SIZE_BYTES = 12
_REGULAR_PAGE_KIND = 2
_COMPRESSED_PAGE_KIND = 3
_SENTINEL_FUNCTION_OFFSET = 0xFFFFFFFF


def _section_int(section: dict[str, Any], primary: str, fallback: str) -> int:
    value = section.get(primary, section.get(fallback, section.get("vaddr", 0)))
    return value if isinstance(value, int) else 0


def macho_image_base(arch_info: dict[str, Any]) -> int | None:
    """Return the optional Mach-O image base used by compact unwind offsets."""
    value = arch_info.get("image_base", 0)
    return value if isinstance(value, int) and value >= 0 else None


def parse_macho_compact_unwind(
    data: bytes,
    sections: list[dict[str, Any]],
    frames: dict[int, ExceptionFrame],
    image_base: int | None,
) -> None:
    """Decode regular and compressed Mach-O compact-unwind pages."""
    if len(data) < _HEADER_SIZE_BYTES:
        return
    version, common_offset, personality_offset, index_offset = struct.unpack_from("<IIII", data, 0)
    if version != 1 or index_offset >= len(data):
        return

    common_end = min(
        (offset for offset in (personality_offset, index_offset) if common_offset < offset <= len(data)),
        default=len(data),
    )
    common_encodings = _read_u32_array(data, common_offset, common_end)
    index_entries = _read_index(data, index_offset)
    if not index_entries:
        return

    compact_entries: dict[int, tuple[int, int]] = {}
    for _index_function_offset, page_offset, _lsda_offset in index_entries:
        for function_offset, encoding, page_kind in _read_page(data, page_offset, common_encodings):
            compact_entries[function_offset] = (encoding, page_kind)

    code_bounds = _text_bounds(sections)
    code_base = code_bounds[0] if code_bounds is not None else image_base
    if code_base is None:
        return
    code_end = code_bounds[1] if code_bounds is not None else None
    starts = sorted(code_base + offset for offset in compact_entries)
    for position, function_start in enumerate(starts):
        next_start = starts[position + 1] if position + 1 < len(starts) else code_end
        function_end = next_start if next_start is not None and next_start > function_start else function_start + 1
        function_offset = function_start - code_base
        encoding, page_kind = compact_entries[function_offset]
        frame = ExceptionFrame(function_start=function_start, function_end=function_end)
        existing = frames.get(function_start)
        if existing is None or function_end > existing.function_end:
            frames[function_start] = frame if existing is None else replace(existing, function_end=function_end)
        logger.debug(
            "Parsed Mach-O compact unwind function at 0x%x (encoding=0x%x, page_kind=%d)",
            function_start,
            encoding,
            page_kind,
        )


def _read_u32_array(data: bytes, offset: int, end: int) -> tuple[int, ...]:
    if offset < 0 or offset >= end or end > len(data):
        return ()
    count = (end - offset) // 4
    return tuple(struct.unpack_from("<I", data, offset + index * 4)[0] for index in range(count))


def _read_index(data: bytes, offset: int) -> tuple[tuple[int, int, int], ...]:
    entries: list[tuple[int, int, int]] = []
    while offset + _INDEX_ENTRY_SIZE_BYTES <= len(data):
        function_offset, page_offset, lsda_offset = struct.unpack_from("<III", data, offset)
        if function_offset == _SENTINEL_FUNCTION_OFFSET:
            break
        if page_offset == 0 or page_offset >= len(data):
            break
        entries.append((function_offset, page_offset, lsda_offset))
        offset += _INDEX_ENTRY_SIZE_BYTES
    return tuple(entries)


def _read_page(data: bytes, page_offset: int, common_encodings: tuple[int, ...]) -> tuple[tuple[int, int, int], ...]:
    if page_offset + 4 > len(data):
        return ()
    page_kind = struct.unpack_from("<I", data, page_offset)[0]
    if page_kind == _REGULAR_PAGE_KIND:
        return _read_regular_page(data, page_offset)
    if page_kind == _COMPRESSED_PAGE_KIND:
        return _read_compressed_page(data, page_offset, common_encodings)
    return ()


def _read_regular_page(data: bytes, page_offset: int) -> tuple[tuple[int, int, int], ...]:
    if page_offset + _REGULAR_PAGE_HEADER_SIZE_BYTES > len(data):
        return ()
    entry_offset, entry_count = struct.unpack_from("<HH", data, page_offset + 4)
    entry_start = page_offset + entry_offset
    entry_end = entry_start + entry_count * 8
    if entry_offset < _REGULAR_PAGE_HEADER_SIZE_BYTES or entry_end > len(data):
        return ()
    return tuple(
        (*struct.unpack_from("<II", data, entry_start + index * 8), _REGULAR_PAGE_KIND) for index in range(entry_count)
    )


def _read_compressed_page(
    data: bytes, page_offset: int, common_encodings: tuple[int, ...]
) -> tuple[tuple[int, int, int], ...]:
    if page_offset + _COMPRESSED_PAGE_HEADER_SIZE_BYTES > len(data):
        return ()
    entry_offset, entry_count, encoding_offset, encoding_count = struct.unpack_from("<HHHH", data, page_offset + 4)
    entry_start = page_offset + entry_offset
    entry_end = entry_start + entry_count * 4
    encoding_start = page_offset + encoding_offset
    encoding_end = encoding_start + encoding_count * 4
    if (
        entry_offset < _COMPRESSED_PAGE_HEADER_SIZE_BYTES
        or entry_end > len(data)
        or encoding_end > len(data)
        or encoding_count == 0
    ):
        return ()
    page_encodings = tuple(
        struct.unpack_from("<I", data, encoding_start + index * 4)[0] for index in range(encoding_count)
    )
    entries: list[tuple[int, int, int]] = []
    for index in range(entry_count):
        packed_entry = struct.unpack_from("<I", data, entry_start + index * 4)[0]
        encoding_index = packed_entry >> 24
        if encoding_index < len(common_encodings):
            encoding = common_encodings[encoding_index]
        else:
            page_encoding_index = encoding_index - len(common_encodings)
            if page_encoding_index >= len(page_encodings):
                return ()
            encoding = page_encodings[page_encoding_index]
        entries.append((packed_entry & 0x00FFFFFF, encoding, _COMPRESSED_PAGE_KIND))
    return tuple(entries)


def _text_bounds(sections: list[dict[str, Any]]) -> tuple[int, int] | None:
    for section in sections:
        name = str(section.get("name", "")).lower()
        if name not in {"__text", ".text"} and not name.endswith(",__text"):
            continue
        address = _section_int(section, "addr", "virtual_address")
        size = _section_int(section, "size", "virtual_size")
        if size > 0:
            return address, address + size
    return None
