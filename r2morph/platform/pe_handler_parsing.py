"""Low-level PE parsing helpers."""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def read_pe_header(binary_path: Path) -> dict[str, Any] | None:
    """Read PE header information from a binary path."""
    try:
        with open(binary_path, "rb") as f:
            if f.read(2) != b"MZ":
                return None

            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]

            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return None

            coff_header = f.read(20)
            if len(coff_header) != 20:
                return None
            coff = parse_coff_header(coff_header)

            optional_header_offset = pe_offset + 24
            f.seek(optional_header_offset)
            magic = struct.unpack("<H", f.read(2))[0]
            is_pe32_plus = magic == 0x20B
            header_size = 240 if is_pe32_plus else 96

            f.seek(optional_header_offset)
            optional_header = f.read(header_size)
            optional = parse_optional_header(optional_header, is_pe32_plus)

            checksum_offset = optional_header_offset + 64

            return {
                "pe_offset": pe_offset,
                "machine": coff["machine"],
                "num_sections": coff["num_sections"],
                "timestamp": coff["timestamp"],
                "size_optional": coff["size_optional"],
                "characteristics": coff["characteristics"],
                "is_pe32_plus": is_pe32_plus,
                "image_base": optional["image_base"],
                "entry_point": optional["entry_point"],
                "section_alignment": optional["section_alignment"],
                "file_alignment": optional["file_alignment"],
                "checksum_offset": checksum_offset,
                "num_data_directories": optional["num_data_directories"],
                "optional_header_offset": optional_header_offset,
            }
    except Exception as e:
        logger.error(f"Failed to read PE header: {e}")
        return None


def get_checksum_offset(binary_path: Path) -> int | None:
    """Get the offset of the PE checksum in the file."""
    try:
        with open(binary_path, "rb") as f:
            if f.read(2) != b"MZ":
                return None
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) != 4:
                return None
            pe_offset = struct.unpack("<I", pe_offset_bytes)[0]

            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return None

            checksum_offset = pe_offset + 24 + 64

            f.seek(0, 2)
            file_size = f.tell()
            if checksum_offset + 4 > file_size:
                return None

            return int(checksum_offset)
    except Exception:
        return None


def calculate_pe_checksum(binary_path: Path) -> int:
    """Calculate PE checksum using Microsoft's algorithm."""
    with open(binary_path, "rb") as f:
        data = f.read()

    checksum_offset = get_checksum_offset(binary_path)
    if checksum_offset is None:
        return sum(data) % (2**32)

    checksum = 0
    for i in range(0, len(data), 4):
        if i == checksum_offset:
            continue

        chunk = data[i : i + 4]
        if len(chunk) < 4:
            chunk = chunk + b"\x00" * (4 - len(chunk))

        word = struct.unpack("<I", chunk)[0]
        checksum = (checksum + word) & 0xFFFFFFFF
        if checksum >= 0x80000000:
            checksum = (checksum & 0x7FFFFFFF) << 1 | 1

    checksum = (checksum + len(data)) & 0xFFFFFFFF
    return checksum


def calculate_simple_checksum(binary_path: Path) -> int:
    """Simple checksum (legacy)."""
    with open(binary_path, "rb") as f:
        data = f.read()
    return sum(data) % (2**32)


def get_sections_fallback(binary_path: Path) -> list[dict[str, Any]]:
    """Parse PE sections without lief by walking the section header table."""
    try:
        sections: list[dict[str, Any]] = []
        with open(binary_path, "rb") as f:
            if f.read(2) != b"MZ":
                return []
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return []
            coff_header = f.read(20)
            if len(coff_header) != 20:
                return []
            _machine, num_sections, _ts, _ptr_sym, _num_sym, size_optional, _chars = struct.unpack(
                "<HHIIIHH", coff_header
            )
            f.seek(size_optional, 1)

            max_sections = 10000
            if num_sections > max_sections:
                logger.warning(f"Excessive section count {num_sections}, limiting to {max_sections}")
                num_sections = max_sections

            for _ in range(num_sections):
                section = f.read(40)
                if len(section) != 40:
                    break
                sections.append(parse_pe_section_entry(section))
        return sections
    except Exception as e:
        logger.error(f"Failed to parse PE sections fallback: {e}")
        return []


def parse_coff_header(coff_header: bytes) -> dict[str, int]:
    """Extract the COFF file-header fields the loader needs."""
    (
        machine,
        num_sections,
        timestamp,
        _ptr_symbols,
        _num_symbols,
        size_optional,
        characteristics,
    ) = struct.unpack("<HHIIIHH", coff_header)
    return {
        "machine": machine,
        "num_sections": num_sections,
        "timestamp": timestamp,
        "size_optional": size_optional,
        "characteristics": characteristics,
    }


def parse_optional_header(optional_header: bytes, is_pe32_plus: bool) -> dict[str, int]:
    """Extract the optional-header fields the loader needs."""
    if is_pe32_plus:
        optional_format = "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII"
        optional_size = 112
    else:
        optional_format = "<HBBIIIII4xIIIHHHHHHIIIIHHIIIIII"
        optional_size = 96

    (
        _magic,
        _major_linker,
        _minor_linker,
        _size_code,
        _size_init_data,
        _size_uninit_data,
        entry_point,
        _base_code,
        image_base,
        section_alignment,
        file_alignment,
        _major_os,
        _minor_os,
        _major_image,
        _minor_image,
        _major_subsys,
        _minor_subsys,
        _win32_version,
        _size_image,
        _size_headers,
        _checksum_offset_raw,
        _subsystem,
        _dll_characteristics,
        _size_stack_reserve,
        _size_stack_commit,
        _size_heap_reserve,
        _size_heap_commit,
        _loader_flags,
        num_rva_sizes,
    ) = struct.unpack(optional_format, optional_header[:optional_size])

    return {
        "entry_point": entry_point,
        "image_base": image_base,
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "num_data_directories": num_rva_sizes,
    }


def parse_pe_section_entry(section: bytes) -> dict[str, Any]:
    """Parse one 40-byte PE section header into a section dict."""
    name = section[0:8].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
    (
        virtual_size,
        virtual_address,
        raw_size,
        raw_ptr,
        _ptr_relocs,
        _ptr_linenos,
        _num_relocs,
        _num_linenos,
        characteristics,
    ) = struct.unpack("<IIIIIIHHI", section[8:40])

    max_section_size = 0x10000000  # 256 MB
    virtual_size = min(virtual_size, max_section_size)
    raw_size = min(raw_size, max_section_size)

    return {
        "name": name,
        "virtual_address": virtual_address,
        "size": max(virtual_size, raw_size),
        "offset": raw_ptr,
        "characteristics": characteristics,
    }

