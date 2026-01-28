"""
ELF (Executable and Linkable Format) specific handling.

This module provides ELF-specific operations for binary analysis and
metamorphic transformation research. It handles section manipulation,
symbol table management, and dynamic linking information.
"""

import logging
import struct
from pathlib import Path
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
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552
PT_GNU_PROPERTY = 0x6474e553


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
                return magic == ELF_MAGIC
        except (OSError, IOError) as e:
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

            # Parse ELF header to validate structure
            header = self._parse_elf_header()
            if header is None:
                return False

            # Validate section header table is within file bounds
            file_size = self.binary_path.stat().st_size
            sh_offset = header["e_shoff"]
            sh_size = header["e_shentsize"] * header["e_shnum"]

            if sh_offset + sh_size > file_size:
                logger.warning(
                    f"Section header table extends beyond file: "
                    f"offset={sh_offset}, size={sh_size}, file_size={file_size}"
                )
                return False

            # Validate program header table is within file bounds
            ph_offset = header["e_phoff"]
            ph_size = header["e_phentsize"] * header["e_phnum"]

            if ph_offset + ph_size > file_size:
                logger.warning(
                    f"Program header table extends beyond file: "
                    f"offset={ph_offset}, size={ph_size}, file_size={file_size}"
                )
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
                elf_class = e_ident[4]
                elf_data = e_ident[5]

                self._is_64bit = elf_class == ELFCLASS64
                self._is_little_endian = elf_data == ELFDATA2LSB

                endian = "<" if self._is_little_endian else ">"

                if self._is_64bit:
                    # 64-bit ELF header format after e_ident
                    # e_type, e_machine, e_version (2+2+4 = 8 bytes)
                    # e_entry, e_phoff, e_shoff (8+8+8 = 24 bytes)
                    # e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
                    # (4+2+2+2+2+2+2 = 16 bytes)
                    fmt = f"{endian}HHI QQQ IHHHHHH"
                    data = f.read(struct.calcsize(fmt))
                    if len(data) < struct.calcsize(fmt):
                        logger.error("Truncated ELF header")
                        return None

                    unpacked = struct.unpack(fmt, data)
                    self._elf_header = {
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
                        "is_64bit": True,
                        "is_little_endian": self._is_little_endian,
                    }
                else:
                    # 32-bit ELF header format after e_ident
                    fmt = f"{endian}HHI III IHHHHHH"
                    data = f.read(struct.calcsize(fmt))
                    if len(data) < struct.calcsize(fmt):
                        logger.error("Truncated ELF header")
                        return None

                    # Fix: 32-bit format has 13 fields, not 12
                    unpacked = struct.unpack(fmt, data)
                    self._elf_header = {
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
                        "is_64bit": False,
                        "is_little_endian": self._is_little_endian,
                    }

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

        return shstrtab_data[name_offset:end].decode("utf-8", errors="replace")

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

                # First, read the section header string table
                shstrtab_data = b""
                if header["e_shstrndx"] < header["e_shnum"]:
                    # Read the shstrtab section header
                    shstrtab_offset = (
                        header["e_shoff"] + header["e_shstrndx"] * header["e_shentsize"]
                    )
                    f.seek(shstrtab_offset)
                    shstrtab_header = f.read(header["e_shentsize"])

                    if is_64bit:
                        # 64-bit section header: sh_offset at bytes 24-32, sh_size at 32-40
                        sh_offset = struct.unpack(f"{endian}Q", shstrtab_header[24:32])[0]
                        sh_size = struct.unpack(f"{endian}Q", shstrtab_header[32:40])[0]
                    else:
                        # 32-bit section header: sh_offset at bytes 16-20, sh_size at 20-24
                        sh_offset = struct.unpack(f"{endian}I", shstrtab_header[16:20])[0]
                        sh_size = struct.unpack(f"{endian}I", shstrtab_header[20:24])[0]

                    f.seek(sh_offset)
                    shstrtab_data = f.read(sh_size)

                # Now read all section headers
                sections = []
                f.seek(header["e_shoff"])

                for i in range(header["e_shnum"]):
                    sh_data = f.read(header["e_shentsize"])
                    if len(sh_data) < header["e_shentsize"]:
                        logger.warning(f"Truncated section header at index {i}")
                        break

                    if is_64bit:
                        # 64-bit section header format
                        # sh_name(4) sh_type(4) sh_flags(8) sh_addr(8) sh_offset(8)
                        # sh_size(8) sh_link(4) sh_info(4) sh_addralign(8) sh_entsize(8)
                        sh_name = struct.unpack(f"{endian}I", sh_data[0:4])[0]
                        sh_type = struct.unpack(f"{endian}I", sh_data[4:8])[0]
                        sh_flags = struct.unpack(f"{endian}Q", sh_data[8:16])[0]
                        sh_addr = struct.unpack(f"{endian}Q", sh_data[16:24])[0]
                        sh_offset = struct.unpack(f"{endian}Q", sh_data[24:32])[0]
                        sh_size = struct.unpack(f"{endian}Q", sh_data[32:40])[0]
                        sh_link = struct.unpack(f"{endian}I", sh_data[40:44])[0]
                        sh_info = struct.unpack(f"{endian}I", sh_data[44:48])[0]
                        sh_addralign = struct.unpack(f"{endian}Q", sh_data[48:56])[0]
                        sh_entsize = struct.unpack(f"{endian}Q", sh_data[56:64])[0]
                    else:
                        # 32-bit section header format
                        # sh_name(4) sh_type(4) sh_flags(4) sh_addr(4) sh_offset(4)
                        # sh_size(4) sh_link(4) sh_info(4) sh_addralign(4) sh_entsize(4)
                        sh_name = struct.unpack(f"{endian}I", sh_data[0:4])[0]
                        sh_type = struct.unpack(f"{endian}I", sh_data[4:8])[0]
                        sh_flags = struct.unpack(f"{endian}I", sh_data[8:12])[0]
                        sh_addr = struct.unpack(f"{endian}I", sh_data[12:16])[0]
                        sh_offset = struct.unpack(f"{endian}I", sh_data[16:20])[0]
                        sh_size = struct.unpack(f"{endian}I", sh_data[20:24])[0]
                        sh_link = struct.unpack(f"{endian}I", sh_data[24:28])[0]
                        sh_info = struct.unpack(f"{endian}I", sh_data[28:32])[0]
                        sh_addralign = struct.unpack(f"{endian}I", sh_data[32:36])[0]
                        sh_entsize = struct.unpack(f"{endian}I", sh_data[36:40])[0]

                    section_name = self._get_section_name(sh_name, shstrtab_data)

                    sections.append({
                        "name": section_name,
                        "vaddr": sh_addr,
                        "size": sh_size,
                        "offset": sh_offset,
                        "flags": sh_flags,
                        "type": sh_type,
                        "link": sh_link,
                        "info": sh_info,
                        "align": sh_addralign,
                        "entsize": sh_entsize,
                        "index": i,
                    })

                logger.debug(f"Parsed {len(sections)} sections from {self.binary_path}")
                return sections

        except Exception as e:
            logger.error(f"Failed to get sections: {e}")
            return []

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

        # Map segment types to names
        type_names = {
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

                    if is_64bit:
                        # 64-bit program header format
                        # p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8)
                        # p_filesz(8) p_memsz(8) p_align(8)
                        p_type = struct.unpack(f"{endian}I", ph_data[0:4])[0]
                        p_flags = struct.unpack(f"{endian}I", ph_data[4:8])[0]
                        p_offset = struct.unpack(f"{endian}Q", ph_data[8:16])[0]
                        p_vaddr = struct.unpack(f"{endian}Q", ph_data[16:24])[0]
                        p_paddr = struct.unpack(f"{endian}Q", ph_data[24:32])[0]
                        p_filesz = struct.unpack(f"{endian}Q", ph_data[32:40])[0]
                        p_memsz = struct.unpack(f"{endian}Q", ph_data[40:48])[0]
                        p_align = struct.unpack(f"{endian}Q", ph_data[48:56])[0]
                    else:
                        # 32-bit program header format
                        # p_type(4) p_offset(4) p_vaddr(4) p_paddr(4)
                        # p_filesz(4) p_memsz(4) p_flags(4) p_align(4)
                        p_type = struct.unpack(f"{endian}I", ph_data[0:4])[0]
                        p_offset = struct.unpack(f"{endian}I", ph_data[4:8])[0]
                        p_vaddr = struct.unpack(f"{endian}I", ph_data[8:12])[0]
                        p_paddr = struct.unpack(f"{endian}I", ph_data[12:16])[0]
                        p_filesz = struct.unpack(f"{endian}I", ph_data[16:20])[0]
                        p_memsz = struct.unpack(f"{endian}I", ph_data[20:24])[0]
                        p_flags = struct.unpack(f"{endian}I", ph_data[24:28])[0]
                        p_align = struct.unpack(f"{endian}I", ph_data[28:32])[0]

                    segments.append({
                        "type": p_type,
                        "type_name": type_names.get(p_type, f"UNKNOWN({p_type})"),
                        "vaddr": p_vaddr,
                        "paddr": p_paddr,
                        "filesz": p_filesz,
                        "memsz": p_memsz,
                        "offset": p_offset,
                        "flags": p_flags,
                        "align": p_align,
                        "index": i,
                    })

                logger.debug(f"Parsed {len(segments)} segments from {self.binary_path}")
                return segments

        except Exception as e:
            logger.error(f"Failed to get segments: {e}")
            return []

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
            logger.error(
                "lief library required for section manipulation. "
                "Install with: pip install lief"
            )
            return None

        try:
            # Parse the ELF binary with lief
            elf = lief.parse(str(self.binary_path))
            if elf is None:
                logger.error(f"Failed to parse ELF with lief: {self.binary_path}")
                return None

            # Check if section already exists
            existing = elf.get_section(name)
            if existing is not None:
                logger.warning(f"Section '{name}' already exists at 0x{existing.virtual_address:x}")
                return existing.virtual_address

            # Create new section
            section = lief.ELF.Section(name)
            section.type = lief.ELF.Section.TYPE.PROGBITS
            section.flags = lief.ELF.Section.FLAGS(flags)
            section.content = [0] * size  # Zero-filled content
            section.alignment = 0x10  # 16-byte alignment

            # Add section to binary
            added_section = elf.add(section, loaded=True)

            if added_section is None:
                logger.error(f"Failed to add section '{name}' to ELF")
                return None

            # Write modified binary back
            elf.write(str(self.binary_path))

            # Clear cached header since file changed
            self._elf_header = None

            vaddr = added_section.virtual_address
            logger.info(
                f"Added ELF section '{name}' ({size} bytes, flags=0x{flags:x}) "
                f"at vaddr 0x{vaddr:x}"
            )
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
            logger.warning(
                "lief library recommended for symbol table parsing. "
                "Install with: pip install lief"
            )
            return {"symtab": [], "dynsym": []}

        try:
            elf = lief.parse(str(self.binary_path))
            if elf is None:
                return {"symtab": [], "dynsym": []}

            result = {"symtab": [], "dynsym": []}

            # Get static symbols
            for sym in elf.static_symbols:
                result["symtab"].append({
                    "name": sym.name,
                    "value": sym.value,
                    "size": sym.size,
                    "type": str(sym.type).split(".")[-1],
                    "binding": str(sym.binding).split(".")[-1],
                    "visibility": str(sym.visibility).split(".")[-1],
                    "shndx": sym.shndx,
                })

            # Get dynamic symbols
            for sym in elf.dynamic_symbols:
                result["dynsym"].append({
                    "name": sym.name,
                    "value": sym.value,
                    "size": sym.size,
                    "type": str(sym.type).split(".")[-1],
                    "binding": str(sym.binding).split(".")[-1],
                    "visibility": str(sym.visibility).split(".")[-1],
                    "shndx": sym.shndx,
                })

            logger.debug(
                f"Found {len(result['symtab'])} static and "
                f"{len(result['dynsym'])} dynamic symbols"
            )
            return result

        except Exception as e:
            logger.error(f"Failed to get symbol tables: {e}")
            return {"symtab": [], "dynsym": []}

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
            logger.warning(
                "lief library required for symbol preservation. "
                "Install with: pip install lief"
            )
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

            logger.info(
                f"Symbol tables intact: {static_count} static, {dynamic_count} dynamic symbols"
            )
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
        return header.get("e_entry")

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

                    # Search for runs of null bytes
                    null_run = 0
                    null_start = -1

                    for i, byte in enumerate(data):
                        if byte == 0:
                            if null_run == 0:
                                null_start = i
                            null_run += 1
                            if null_run >= min_size:
                                vaddr = section["vaddr"] + null_start
                                logger.info(
                                    f"Found code cave: {null_run} bytes at "
                                    f"0x{vaddr:x} in {section['name']}"
                                )
                                return vaddr
                        else:
                            null_run = 0

            logger.debug(f"No code cave of {min_size}+ bytes found")
            return None

        except Exception as e:
            logger.error(f"Failed to find code cave: {e}")
            return None
