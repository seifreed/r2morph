"""
ELF (Executable and Linkable Format) specific handling.

This module provides ELF-specific operations for binary analysis and
metamorphic transformation research. It handles section manipulation,
symbol table management, and dynamic linking information.
"""

import logging
from pathlib import Path
from typing import Any, BinaryIO

from r2morph.platform.elf_handler_code_caves import find_code_cave as project_find_code_cave
from r2morph.platform.elf_handler_metadata import get_architecture as project_architecture
from r2morph.platform.elf_handler_metadata import get_entry_point as project_entry_point
from r2morph.platform.elf_handler_parsing import get_section_name, parse_elf_header, read_shstrtab
from r2morph.platform.elf_handler_symbol_preservation import preserve_symbols as check_symbol_preservation
from r2morph.platform.elf_handler_symbols import collect_symbol_tables
from r2morph.platform.elf_handler_tables import collect_sections, collect_segments
from r2morph.platform.elf_handler_validation import validate_elf_file_structure
from r2morph.platform.elf_structs import ELF_MAGIC, SHF_EXECINSTR

logger = logging.getLogger(__name__)


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

            return validate_elf_file_structure(self.binary_path, header)

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

        self._elf_header, self._is_64bit, self._is_little_endian = parse_elf_header(self.binary_path)
        return self._elf_header

    def _get_section_name(self, name_offset: int, shstrtab_data: bytes) -> str:
        """Extract section name from the section header string table.

        Args:
            name_offset: Offset into the string table.
            shstrtab_data: The section header string table data.

        Returns:
            The section name as a string.
        """
        return get_section_name(name_offset, shstrtab_data)

    @staticmethod
    def _read_shstrtab(f: BinaryIO, header: dict[str, Any], file_size: int) -> bytes:
        """Read the section header string table bytes, or b'' if unavailable.

        Each failed bounds check logs a warning and yields an empty table, so
        section names simply fall back to offsets downstream.
        """
        return read_shstrtab(f, header, file_size)

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
                return collect_sections(self.binary_path, header, f)
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

        try:
            with open(self.binary_path, "rb") as f:
                return collect_segments(self.binary_path, header, f)
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
        return collect_symbol_tables(self.binary_path)

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
        return check_symbol_preservation(self.binary_path)

    def get_entry_point(self) -> int | None:
        """Get the entry point address of the ELF binary.

        Returns:
            The virtual address of the entry point, or None if parsing fails.
        """
        return project_entry_point(self._parse_elf_header())

    def get_architecture(self) -> dict[str, Any]:
        """Get architecture information from the ELF binary.

        Returns:
            Dictionary with architecture details:
                - machine (int): Machine type value
                - machine_name (str): Human-readable machine name
                - bits (int): 32 or 64
                - endian (str): "little" or "big"
        """
        return project_architecture(self._parse_elf_header())

    def find_code_cave(self, min_size: int = 64) -> int | None:
        """Find a code cave (unused space) in the ELF binary.

        Searches for regions of null bytes within executable sections that
        could be used for code injection.

        Args:
            min_size: Minimum size of the code cave in bytes.

        Returns:
            Virtual address of the code cave, or None if not found.
        """
        return project_find_code_cave(self.binary_path, self.get_sections(), min_size)


__all__ = ["ELFHandler", "SHF_EXECINSTR"]
