"""
ELF (Executable and Linkable Format) specific handling.

This module provides ELF-specific operations for binary analysis and
metamorphic transformation research. It handles section manipulation,
symbol table management, and dynamic linking information.
"""

import logging
import struct
from pathlib import Path
from typing import Any, BinaryIO

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


class ELFHandler:
    """Handles ELF-specific operations for binary analysis and transformation.

    This handler provides methods for:
        - Section enumeration and manipulation
        - Symbol table preservation during transformations
        - Dynamic linking information management
        - ELF validation and segment analysis

    Attributes:
        binary_path: Path to the ELF binary file being analyzed.

    Example:
        >>> handler = ELFHandler(Path("/path/to/binary"))
        >>> if handler.is_elf():
        ...     sections = handler.get_sections()
        ...     handler.add_section(".morph", 4096)
    """

    def __init__(self, binary_path: Path) -> None:
        """Initialize the ELF handler with a binary path.

        Args:
            binary_path: Path to the ELF binary file to analyze or transform.
        """
        self.binary_path = Path(binary_path)
        self._elf_header: dict[str, Any] | None = None
        self._is_64bit: bool | None = None
        self._is_little_endian: bool | None = None
        logger.debug(f"Initialized ELFHandler for: {binary_path}")

    def is_elf(self) -> bool:
        """Check if the binary is a valid ELF file.

        Returns:
            True if the file has a valid ELF magic number, False otherwise.
        """
        try:
            with open(self.binary_path, "rb") as f:
                magic = f.read(4)
                if len(magic) < 4:
                    return False
                return magic == ELF_MAGIC
        except OSError as e:
            logger.error(f"Failed to read file for ELF check: {e}")
            return False

    def validate(self) -> bool:
        """Validate the ELF file structure.

        Performs comprehensive validation of the ELF file including:
        - Magic number verification
        - Header structure validation
        - Section header table bounds checking

        Returns:
            True if the ELF file appears to be valid, False otherwise.
        """
        try:
            if not self.is_elf():
                logger.warning(f"Not a valid ELF file: {self.binary_path}")
                return False

            header = self._parse_elf_header()
            if header is None:
                return False

            file_size = self.binary_path.stat().st_size

            sh_size = header["e_shentsize"] * header["e_shnum"]
            if not _header_table_within_file(header["e_shoff"], sh_size, file_size, "Section header table"):
                return False

            ph_size = header["e_phentsize"] * header["e_phnum"]
            if not _header_table_within_file(header["e_phoff"], ph_size, file_size, "Program header table"):
                return False

            logger.debug(f"ELF validation passed for: {self.binary_path}")
            return True

        except Exception as e:
            logger.error(f"ELF validation failed: {e}")
            return False

    def _parse_elf_header(self) -> dict[str, Any] | None:
        """Parse the ELF header and cache the result.

        Returns:
            Dictionary containing ELF header fields, or None if parsing fails.
        """
        if self._elf_header is not None:
            return self._elf_header

        try:
            with open(self.binary_path, "rb") as f:
                # Read e_ident (16 bytes)
                e_ident = f.read(16)
                if len(e_ident) < 16 or e_ident[:4] != ELF_MAGIC:
                    logger.error("Invalid ELF magic number")
                    return None

                # Determine class (32/64-bit) and endianness
                self._is_64bit = e_ident[4] == ELFCLASS64
                self._is_little_endian = e_ident[5] == ELFDATA2LSB

                endian = "<" if self._is_little_endian else ">"
                # The header after e_ident shares one field order across classes;
                # only e_entry/e_phoff/e_shoff change width (8 bytes vs 4 bytes).
                offset_fields = "QQQ" if self._is_64bit else "III"
                fmt = f"{endian}HHI {offset_fields} IHHHHHH"

                data = f.read(struct.calcsize(fmt))
                if len(data) < struct.calcsize(fmt):
                    logger.error("Truncated ELF header")
                    return None

                self._elf_header = _build_elf_header_dict(
                    e_ident,
                    struct.unpack(fmt, data),
                    is_64bit=self._is_64bit,
                    is_little_endian=self._is_little_endian,
                )
                return self._elf_header

        except Exception as e:
            logger.error(f"Failed to parse ELF header: {e}")
            return None

    def _get_section_name(self, name_offset: int, shstrtab_data: bytes) -> str:
        """Extract section name from the section header string table.

        Args:
            name_offset: Offset into the string table.
            shstrtab_data: The section header string table data.

        Returns:
            The section name as a string.
        """
        if name_offset >= len(shstrtab_data):
            return ""

        end = shstrtab_data.find(b"\x00", name_offset)
        if end == -1:
            end = len(shstrtab_data)

        if end - name_offset > MAX_SECTION_NAME:
            end = name_offset + MAX_SECTION_NAME

        return shstrtab_data[name_offset:end].decode("utf-8", errors="replace")

    @staticmethod
    def _read_shstrtab(f: BinaryIO, header: dict[str, Any], file_size: int) -> bytes:
        """Read the section header string table bytes, or b'' if unavailable.

        Each failed bounds check logs a warning and yields an empty table, so
        section names simply fall back to offsets downstream.
        """
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

    def get_sections(self) -> list[dict[str, Any]]:
        """Retrieve all sections from the ELF binary.

        Parses the ELF section header table and returns information about
        each section including name, size, virtual address, and flags.

        Returns:
            List of section dictionaries, each containing:
                - name (str): Section name (e.g., ".text", ".data")
                - vaddr (int): Virtual address
                - size (int): Section size in bytes
                - offset (int): File offset
                - flags (int): Section flags
                - type (int): Section type
                - align (int): Section alignment

        Example:
            >>> handler = ELFHandler(Path("/bin/ls"))
            >>> sections = handler.get_sections()
            >>> for s in sections:
            ...     print(f"{s['name']}: 0x{s['vaddr']:x}, {s['size']} bytes")
        """
        header = self._parse_elf_header()
        if header is None:
            logger.error(f"Failed to parse ELF header for: {self.binary_path}")
            return []

        try:
            with open(self.binary_path, "rb") as f:
                is_64bit = header["is_64bit"]
                endian = "<" if header["is_little_endian"] else ">"

                file_size = self.binary_path.stat().st_size

                shstrtab_data = self._read_shstrtab(f, header, file_size)

                # Now read all section headers
                sections = []
                f.seek(header["e_shoff"])

                section_count = min(header["e_shnum"], MAX_SECTIONS)
                section_entry_size = min(header["e_shentsize"], MAX_SECTION_ENTRY_SIZE)

                if header["e_shnum"] > MAX_SECTIONS:
                    logger.warning(f"Excessive section count {header['e_shnum']}, limiting to {MAX_SECTIONS}")
                if header["e_shentsize"] > MAX_SECTION_ENTRY_SIZE:
                    logger.warning(
                        f"Excessive section entry size {header['e_shentsize']}, limiting to {MAX_SECTION_ENTRY_SIZE}"
                    )

                for i in range(section_count):
                    sh_data = f.read(section_entry_size)
                    if len(sh_data) < section_entry_size:
                        logger.warning(f"Truncated section header at index {i}")
                        break

                    entry = self._parse_section_header_entry(sh_data, is_64bit, endian)
                    section_name = self._get_section_name(entry["sh_name"], shstrtab_data)
                    sections.append(_build_section_dict(entry, section_name, i))

                logger.debug(f"Parsed {len(sections)} sections from {self.binary_path}")
                return sections

        except Exception as e:
            logger.error(f"Failed to get sections: {e}")
            return []

    @staticmethod
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

    def get_segments(self) -> list[dict[str, Any]]:
        """Retrieve all program segments (program headers) from the ELF binary.

        Parses the ELF program header table and returns information about
        each segment including type, virtual address, and permissions.

        Returns:
            List of segment dictionaries, each containing:
                - type (int): Segment type (PT_LOAD, PT_DYNAMIC, etc.)
                - type_name (str): Human-readable segment type name
                - vaddr (int): Virtual address
                - paddr (int): Physical address
                - filesz (int): Size in file
                - memsz (int): Size in memory
                - offset (int): File offset
                - flags (int): Segment flags (read/write/execute)
                - align (int): Segment alignment

        Example:
            >>> handler = ELFHandler(Path("/bin/ls"))
            >>> segments = handler.get_segments()
            >>> for s in segments:
            ...     print(f"{s['type_name']}: 0x{s['vaddr']:x}")
        """
        header = self._parse_elf_header()
        if header is None:
            logger.error(f"Failed to parse ELF header for: {self.binary_path}")
            return []

        try:
            with open(self.binary_path, "rb") as f:
                is_64bit = header["is_64bit"]
                endian = "<" if header["is_little_endian"] else ">"

                segments = []
                f.seek(header["e_phoff"])

                for i in range(header["e_phnum"]):
                    ph_data = f.read(header["e_phentsize"])
                    if len(ph_data) < header["e_phentsize"]:
                        logger.warning(f"Truncated program header at index {i}")
                        break

                    entry = self._parse_program_header_entry(ph_data, is_64bit, endian)
                    segments.append(_build_segment_dict(entry, i))

                logger.debug(f"Parsed {len(segments)} segments from {self.binary_path}")
                return segments

        except Exception as e:
            logger.error(f"Failed to get segments: {e}")
            return []

    @staticmethod
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

    def add_section(self, name: str, size: int, flags: int = 0x6) -> int | None:
        """Add a new section to the ELF binary.

        This method adds a new section with the specified parameters to enable
        code injection, data storage, or transformation workspace. Uses the
        lief library for safe and reliable ELF manipulation.

        Args:
            name: Section name (e.g., ".morph", ".stub"). Should follow ELF
                naming conventions (typically starts with ".").
            size: Section size in bytes. Will be aligned appropriately.
            flags: Section flags as defined in ELF specification. Default is
                0x6 (SHF_ALLOC | SHF_WRITE) for read-write data sections.
                Common values:
                    - 0x2: SHF_ALLOC (occupies memory during execution)
                    - 0x4: SHF_EXECINSTR (executable instructions)
                    - 0x6: SHF_ALLOC | SHF_WRITE (read-write data)
                    - 0x7: SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR (rwx)

        Returns:
            Virtual address of the new section if successful, or None if
            the operation fails or lief is not available.

        Raises:
            ImportError: When lief library is not installed (logged, not raised).

        Example:
            >>> handler = ELFHandler(Path("/path/to/binary"))
            >>> vaddr = handler.add_section(".morph", 4096, flags=0x6)
            >>> if vaddr:
            ...     print(f"New section at: 0x{vaddr:x}")
        """
        try:
            import lief
        except ImportError:
            logger.error("lief library required for section manipulation. Install with: pip install lief")
            return None

        try:
            elf = lief.parse(str(self.binary_path))
            if elf is None:
                logger.error(f"Failed to parse ELF with lief: {self.binary_path}")
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
            section.content = list(bytes(size))  # Zero-filled content
            section.alignment = 0x10  # 16-byte alignment

            added_section = elf.add(section, loaded=True)

            if added_section is None:
                logger.error(f"Failed to add section '{name}' to ELF")
                return None

            elf.write(str(self.binary_path))

            self._elf_header = None

            vaddr = added_section.virtual_address
            logger.info(f"Added ELF section '{name}' ({size} bytes, flags=0x{flags:x}) at vaddr 0x{vaddr:x}")
            return vaddr

        except Exception as e:
            logger.error(f"Failed to add section '{name}': {e}")
            return None

    def get_symbol_tables(self) -> dict[str, list[dict[str, Any]]]:
        """Get symbol table information from the ELF binary.

        Retrieves both the static symbol table (.symtab) and dynamic symbol
        table (.dynsym) if present.

        Returns:
            Dictionary with keys 'symtab' and 'dynsym', each containing a list
            of symbol dictionaries with name, value, size, type, and binding.
        """
        try:
            import lief
        except ImportError:
            logger.warning("lief library recommended for symbol table parsing. Install with: pip install lief")
            return {"symtab": [], "dynsym": []}

        try:
            elf = lief.parse(str(self.binary_path))
            if elf is None or not isinstance(elf, lief.ELF.Binary):
                return {"symtab": [], "dynsym": []}

            result = {
                "symtab": self._collect_symbols(elf.symtab_symbols, label="symbol table"),
                "dynsym": self._collect_symbols(elf.dynamic_symbols, label="dynamic symbol table"),
            }
            logger.debug(f"Found {len(result['symtab'])} static and {len(result['dynsym'])} dynamic symbols")
            return result

        except Exception as e:
            logger.error(f"Failed to get symbol tables: {e}")
            return {"symtab": [], "dynsym": []}

    @staticmethod
    def _collect_symbols(symbols: Any, *, label: str) -> list[dict[str, Any]]:
        """Build symbol dicts from a lief symbol iterable, capped at MAX_SYMBOLS."""
        collected: list[dict[str, Any]] = []
        for sym in symbols:
            if len(collected) >= MAX_SYMBOLS:
                logger.warning(f"Truncating {label} at {MAX_SYMBOLS} entries")
                break
            collected.append(
                {
                    "name": sym.name,
                    "value": sym.value,
                    "size": sym.size,
                    "type": str(sym.type).split(".")[-1],
                    "binding": str(sym.binding).split(".")[-1],
                    "visibility": str(sym.visibility).split(".")[-1],
                    "shndx": sym.shndx,
                }
            )
        return collected

    def preserve_symbols(self) -> bool:
        """Preserve symbol table integrity after binary transformations.

        This method ensures that the symbol table (.symtab) and dynamic
        symbol table (.dynsym) remain valid after metamorphic transformations
        are applied to the binary. This is critical for:
            - Maintaining debuggability
            - Preserving dynamic linking functionality
            - Allowing symbol resolution in transformed binaries

        Returns:
            True if symbol preservation was successful. False if preservation
            failed or if the necessary library (lief) is not available.

        Note:
            This method currently validates that symbol tables are intact.
            For actual address remapping after transformations, additional
            tracking of code movements would be required.
        """
        try:
            import lief
        except ImportError:
            logger.warning("lief library required for symbol preservation. Install with: pip install lief")
            return False

        try:
            elf = lief.parse(str(self.binary_path))
            if elf is None:
                logger.error(f"Failed to parse ELF for symbol preservation: {self.binary_path}")
                return False

            # Verify symbol tables are accessible (lief API varies by version)
            if hasattr(elf, "static_symbols"):
                static_symbols = list(elf.static_symbols)
            else:
                static_symbols = list(getattr(elf, "symbols", []))
            if hasattr(elf, "dynamic_symbols"):
                dynamic_symbols = list(elf.dynamic_symbols)
            else:
                dynamic_symbols = list(getattr(elf, "dynamic_symbols", []))

            static_count = len(static_symbols)
            dynamic_count = len(dynamic_symbols)

            logger.info(f"Symbol tables intact: {static_count} static, {dynamic_count} dynamic symbols")
            return True

        except Exception as e:
            logger.error(f"Symbol preservation check failed: {e}")
            return False

    def get_entry_point(self) -> int | None:
        """Get the entry point address of the ELF binary.

        Returns:
            The virtual address of the entry point, or None if parsing fails.
        """
        header = self._parse_elf_header()
        if header is None:
            return None
        entry = header.get("e_entry")
        return int(entry) if entry is not None else None

    def get_architecture(self) -> dict[str, Any]:
        """Get architecture information from the ELF binary.

        Returns:
            Dictionary with architecture details:
                - machine (int): Machine type value
                - machine_name (str): Human-readable machine name
                - bits (int): 32 or 64
                - endian (str): "little" or "big"
        """
        header = self._parse_elf_header()
        if header is None:
            return {}

        # Common machine types
        machine_names = {
            0x03: "x86",
            0x3E: "x86_64",
            0x28: "ARM",
            0xB7: "AArch64",
            0x08: "MIPS",
            0x14: "PowerPC",
            0x15: "PowerPC64",
            0xF3: "RISC-V",
        }

        machine = header.get("e_machine", 0)
        return {
            "machine": machine,
            "machine_name": machine_names.get(machine, f"Unknown({machine})"),
            "bits": 64 if header.get("is_64bit") else 32,
            "endian": "little" if header.get("is_little_endian") else "big",
        }

    def find_code_cave(self, min_size: int = 64) -> int | None:
        """Find a code cave (unused space) in the ELF binary.

        Searches for regions of null bytes within executable sections that
        could be used for code injection.

        Args:
            min_size: Minimum size of the code cave in bytes.

        Returns:
            Virtual address of the code cave, or None if not found.
        """
        sections = self.get_sections()

        try:
            with open(self.binary_path, "rb") as f:
                for section in sections:
                    # Look in executable sections
                    if not (section["flags"] & SHF_EXECINSTR):
                        continue

                    # Skip sections that are too small
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

        except Exception as e:
            logger.error(f"Failed to find code cave: {e}")
            return None
