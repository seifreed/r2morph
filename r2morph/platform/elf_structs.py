"""ELF on-disk format definitions and stateless structure codecs.

This module owns the ELF format constants and the pure, stateless functions
that unpack raw header bytes into field dicts and assemble the higher-level
section/segment/header dicts. It performs no file I/O and holds no per-binary
state; :mod:`r2morph.platform.elf_handler` layers the stateful operations on
top of these primitives.
"""

import logging
import struct
from typing import Any

logger = logging.getLogger(__name__)

# ELF Magic number
ELF_MAGIC = b"\x7fELF"

# ELF Class (32-bit vs 64-bit)
ELFCLASS32 = 1
ELFCLASS64 = 2

# ELF Data encoding (endianness)
ELFDATA2LSB = 1  # Little endian
ELFDATA2MSB = 2  # Big endian

# Section header types
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11

# Section flags
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# Program header types
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_GNU_PROPERTY = 0x6474E553

# Sanity bounds when parsing untrusted ELF data
MAX_SECTION_NAME = 256
MAX_SECTIONS = 10000
MAX_SECTION_ENTRY_SIZE = 1024
MAX_SYMBOLS = 100000


def _build_elf_header_dict(
    e_ident: bytes,
    unpacked: tuple[int, ...],
    *,
    is_64bit: bool,
    is_little_endian: bool,
) -> dict[str, Any]:
    """Assemble the ELF header dict from the unpacked fixed-size fields.

    The 64-bit and 32-bit headers share this field order; only the width of
    e_entry/e_phoff/e_shoff differs, which is handled by the caller's format.
    """
    return {
        "e_ident": e_ident,
        "e_type": unpacked[0],
        "e_machine": unpacked[1],
        "e_version": unpacked[2],
        "e_entry": unpacked[3],
        "e_phoff": unpacked[4],
        "e_shoff": unpacked[5],
        "e_flags": unpacked[6],
        "e_ehsize": unpacked[7],
        "e_phentsize": unpacked[8],
        "e_phnum": unpacked[9],
        "e_shentsize": unpacked[10],
        "e_shnum": unpacked[11],
        "e_shstrndx": unpacked[12],
        "is_64bit": is_64bit,
        "is_little_endian": is_little_endian,
    }


# Program-header (segment) type values mapped to their human-readable names.
_PT_TYPE_NAMES = {
    PT_NULL: "NULL",
    PT_LOAD: "LOAD",
    PT_DYNAMIC: "DYNAMIC",
    PT_INTERP: "INTERP",
    PT_NOTE: "NOTE",
    PT_SHLIB: "SHLIB",
    PT_PHDR: "PHDR",
    PT_TLS: "TLS",
    PT_GNU_EH_FRAME: "GNU_EH_FRAME",
    PT_GNU_STACK: "GNU_STACK",
    PT_GNU_RELRO: "GNU_RELRO",
    PT_GNU_PROPERTY: "GNU_PROPERTY",
}


def _build_segment_dict(entry: dict[str, int], index: int) -> dict[str, Any]:
    """Assemble a program-segment dict from a parsed program-header entry."""
    p_type = entry["p_type"]
    return {
        "type": p_type,
        "type_name": _PT_TYPE_NAMES.get(p_type, f"UNKNOWN({p_type})"),
        "vaddr": entry["p_vaddr"],
        "paddr": entry["p_paddr"],
        "filesz": entry["p_filesz"],
        "memsz": entry["p_memsz"],
        "offset": entry["p_offset"],
        "flags": entry["p_flags"],
        "align": entry["p_align"],
        "index": index,
    }


def _build_section_dict(entry: dict[str, int], section_name: str, index: int) -> dict[str, Any]:
    """Assemble a section dict from a parsed section-header entry."""
    return {
        "name": section_name,
        "vaddr": entry["sh_addr"],
        "size": entry["sh_size"],
        "offset": entry["sh_offset"],
        "flags": entry["sh_flags"],
        "type": entry["sh_type"],
        "link": entry["sh_link"],
        "info": entry["sh_info"],
        "align": entry["sh_addralign"],
        "entsize": entry["sh_entsize"],
        "index": index,
    }


def _find_null_run(data: bytes, min_size: int) -> int | None:
    """Return the start offset of the first run of at least min_size null bytes."""
    null_run = 0
    null_start = -1
    for i, byte in enumerate(data):
        if byte == 0:
            if null_run == 0:
                null_start = i
            null_run += 1
            if null_run >= min_size:
                return null_start
        else:
            null_run = 0
    return None


def _header_table_within_file(offset: int, size: int, file_size: int, label: str) -> bool:
    """Return whether a header table fits in the file, warning if it overflows."""
    if offset + size > file_size:
        logger.warning(f"{label} extends beyond file: offset={offset}, size={size}, file_size={file_size}")
        return False
    return True


def _parse_section_header_entry(sh_data: bytes, is_64bit: bool, endian: str) -> dict[str, int]:
    """Unpack one ELF section-header table entry.

    The 32- and 64-bit layouts carry the same ten fields in the same
    order; sh_flags/sh_addr/sh_offset/sh_size/sh_addralign/sh_entsize widen
    from 4 to 8 bytes in the 64-bit format. The ``endian`` byte-order prefix
    ("<" or ">") selects standard sizes with no struct padding, so the
    combined format matches the field offsets exactly.
    """
    if is_64bit:
        fmt = f"{endian}IIQQQQIIQQ"
        entry_size = 64
    else:
        fmt = f"{endian}IIIIIIIIII"
        entry_size = 40

    (
        sh_name,
        sh_type,
        sh_flags,
        sh_addr,
        sh_offset,
        sh_size,
        sh_link,
        sh_info,
        sh_addralign,
        sh_entsize,
    ) = struct.unpack(fmt, sh_data[:entry_size])

    return {
        "sh_name": sh_name,
        "sh_type": sh_type,
        "sh_flags": sh_flags,
        "sh_addr": sh_addr,
        "sh_offset": sh_offset,
        "sh_size": sh_size,
        "sh_link": sh_link,
        "sh_info": sh_info,
        "sh_addralign": sh_addralign,
        "sh_entsize": sh_entsize,
    }


def _parse_program_header_entry(ph_data: bytes, is_64bit: bool, endian: str) -> dict[str, int]:
    """Unpack one ELF program-header table entry.

    ELF32 and ELF64 reorder p_flags: it follows p_type in the 64-bit
    layout but sits between p_memsz and p_align in the 32-bit layout. The
    offset/vaddr/paddr/filesz/memsz/align fields widen from 4 to 8 bytes in
    the 64-bit format. With an explicit "<"/">" byte order struct adds no
    padding, so each combined format matches the field offsets exactly.
    """
    if is_64bit:
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
            f"{endian}IIQQQQQQ", ph_data[:56]
        )
    else:
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
            f"{endian}IIIIIIII", ph_data[:32]
        )

    return {
        "p_type": p_type,
        "p_flags": p_flags,
        "p_offset": p_offset,
        "p_vaddr": p_vaddr,
        "p_paddr": p_paddr,
        "p_filesz": p_filesz,
        "p_memsz": p_memsz,
        "p_align": p_align,
    }
