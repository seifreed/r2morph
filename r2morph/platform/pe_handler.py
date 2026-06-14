"""
PE (Portable Executable) format specific handling.

Handles:
- Checksum fixes
- Section manipulation
- Import/Export table integrity
- Relocation directory validation
- PE header repair after mutations
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from r2morph.platform.pe_handler_parsing import (
    calculate_pe_checksum,
    calculate_simple_checksum,
    get_checksum_offset,
    get_sections_fallback,
    parse_coff_header,
    parse_optional_header,
    parse_pe_section_entry,
    read_pe_header,
)
from r2morph.platform.pe_handler_repair import (
    fix_checksum as repair_fix_checksum,
)
from r2morph.platform.pe_handler_repair import (
    fix_exports as repair_fix_exports,
)
from r2morph.platform.pe_handler_repair import (
    fix_imports as repair_fix_imports,
)
from r2morph.platform.pe_handler_repair import (
    fix_resources as repair_fix_resources,
)
from r2morph.platform.pe_handler_repair import (
    full_repair as repair_full_repair,
)
from r2morph.platform.pe_handler_repair import (
    get_stored_checksum as repair_get_stored_checksum,
)
from r2morph.platform.pe_handler_repair import (
    refresh_headers as repair_refresh_headers,
)
from r2morph.platform.pe_handler_repair import (
    repair_integrity as repair_repair_integrity,
)
from r2morph.platform.pe_handler_repair import (
    validate_integrity as repair_validate_integrity,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import lief
else:
    try:
        import lief
    except ImportError:
        lief = None

LIEF_AVAILABLE = lief is not None


class PEHandler:
    """
    Handles PE-specific operations.

    - Checksum fixes
    - Section manipulation
    - Import table updates
    - Resource preservation
    - Relocation directory repair
    """

    def __init__(self, binary_path: Path):
        """
        Initialize PE handler.

        Args:
            binary_path: Path to PE file
        """
        self.binary_path = binary_path
        self._binary: Any = None
        self._pe_offset: int | None = None
        self._sections_cache: list[dict] | None = None

    def _parse_lief(self) -> Any:
        if lief is None:
            return None
        try:
            binary = lief.parse(str(self.binary_path))
            if isinstance(binary, lief.PE.Binary):
                self._binary = binary
                return binary
            return None
        except Exception as e:
            logger.error(f"Failed to parse PE with LIEF: {e}")
            return None

    def _read_pe_header(self) -> dict[str, Any] | None:
        """Read PE header information."""
        header = read_pe_header(self.binary_path)
        if header is not None:
            self._pe_offset = header["pe_offset"]
        return header

    @staticmethod
    def _parse_coff_header(coff_header: bytes) -> dict[str, int]:
        """Extract the COFF file-header fields the loader needs."""
        return parse_coff_header(coff_header)

    @staticmethod
    def _parse_optional_header(optional_header: bytes, is_pe32_plus: bool) -> dict[str, int]:
        """Extract the optional-header fields the loader needs.

        PE32 and PE32+ optional headers destructure to the same 29 fields
        (sans data directories); only the struct format and length differ.
        PE32+ widens ImageBase and the four stack/heap sizes to 8 bytes
        (``Q``); PE32 instead carries a 4-byte BaseOfData between BaseOfCode
        and ImageBase, skipped with ``4x`` so both layouts stay field-aligned.
        Both match lief/pefile field-for-field (verified on
        dataset/pe_x86_64.exe, a PE32+ x86_64 file).
        """
        return parse_optional_header(optional_header, is_pe32_plus)

    def is_pe(self) -> bool:
        """Check if the file is a PE binary."""
        try:
            with open(self.binary_path, "rb") as f:
                if f.read(2) != b"MZ":
                    return False
                f.seek(0x3C)
                pe_offset = int.from_bytes(f.read(4), "little")
                f.seek(pe_offset)
                return f.read(4) == b"PE\x00\x00"
        except Exception:
            return False

    def get_checksum_offset(self) -> int | None:
        """
        Get the offset of the PE checksum in the file.

        Note: The checksum offset is at the same position (64 bytes from optional header start)
        for both PE32 and PE32+ formats.

        Returns:
            Offset of checksum field or None
        """
        return get_checksum_offset(self.binary_path)

    def fix_checksum(self) -> bool:
        """Recalculate and fix PE checksum."""
        return repair_fix_checksum(self)

    def _calculate_pe_checksum(self) -> int:
        """
        Calculate PE checksum using Microsoft's algorithm.

        Returns:
            Checksum value
        """
        return calculate_pe_checksum(self.binary_path)

    def _calculate_checksum(self) -> int:
        """Simple checksum (legacy)."""
        return calculate_simple_checksum(self.binary_path)

    def get_sections(self) -> list[dict]:
        """
        Get PE sections.

        Returns:
            List of section dicts
        """
        if self._sections_cache is not None:
            return self._sections_cache

        logger.debug("Getting PE sections")
        binary = self._parse_lief()
        if binary is not None:
            sections = [
                {
                    "name": section.name,
                    "virtual_address": section.virtual_address,
                    "virtual_size": section.virtual_size,
                    "raw_size": section.size,
                    "offset": section.offset,
                    "characteristics": section.characteristics,
                }
                for section in binary.sections
            ]
        else:
            sections = self._get_sections_fallback()

        self._sections_cache = sections
        return sections

    def _get_sections_fallback(self) -> list[dict]:
        """Parse PE sections without lief by walking the section header table."""
        return get_sections_fallback(self.binary_path)

    @staticmethod
    def _parse_pe_section_entry(section: bytes) -> dict:
        """Parse one 40-byte PE section header into a section dict.

        Layout: 8-byte name + 6xI (VirtualSize, VirtualAddress, SizeOfRawData,
        PointerToRawData, PointerToRelocations, PointerToLineNumbers) + 2xH
        (NumberOfRelocations, NumberOfLineNumbers -- u16, not u32) + 1xI
        Characteristics. VirtualSize and SizeOfRawData are clamped to 256 MB to
        reject corrupt headers.
        """
        return parse_pe_section_entry(section)

    def get_imports(self) -> list[dict]:
        """Get PE imports."""
        binary = self._parse_lief()
        if binary is None:
            return []
        imports: list[dict] = []
        for entry in binary.imports:
            items = []
            for func in entry.entries:
                if func.name:
                    items.append(func.name)
                else:
                    items.append(func.ordinal)
            imports.append({"library": entry.name, "entries": items})
        return imports

    def get_exports(self) -> list[dict]:
        """Get PE exports."""
        binary = self._parse_lief()
        if binary is None:
            return []
        exports: list[dict] = []
        for func in binary.exported_functions:
            exports.append(
                {
                    "name": func.name if hasattr(func, "name") else None,
                    "address": func.address if hasattr(func, "address") else None,
                    "ordinal": func.ordinal if hasattr(func, "ordinal") else None,
                }
            )
        return exports

    def get_relocations(self) -> list[dict]:
        """
        Get PE relocation entries.

        Returns:
            List of relocation dict entries
        """
        binary = self._parse_lief()
        if binary is None:
            return []

        relocations: list[dict] = []
        for reloc in binary.relocations:
            relocations.append(
                {
                    "address": reloc.address,
                    "size": reloc.size,
                    "type": str(reloc.type),
                }
            )
        return relocations

    def validate_integrity(self) -> tuple[bool, list[str]]:
        """Validate PE integrity after mutation."""
        return repair_validate_integrity(self)

    def _get_stored_checksum(self) -> int:
        """Get the stored checksum from the PE header."""
        return repair_get_stored_checksum(self)

    def repair_integrity(self) -> tuple[bool, list[str]]:
        """Repair PE integrity after mutation."""
        return repair_repair_integrity(self)

    def validate(self) -> bool:
        """Validate PE structure."""
        if not self.is_pe():
            return False
        if lief is None:
            return True
        return self._parse_lief() is not None

    def add_section(self, name: str, size: int, characteristics: int = 0x60000020) -> int | None:
        """
        Add a new section to PE.

        Args:
            name: Section name (max 8 chars)
            size: Section size
            characteristics: Section flags

        Returns:
            Virtual address of new section, or None
        """
        if lief is None:
            logger.error("lief required for PE section creation")
            return None

        try:
            parsed = lief.parse(str(self.binary_path))
            if parsed is None or not isinstance(parsed, lief.PE.Binary):
                logger.error("Failed to parse PE binary with lief")
                return None

            section = lief.PE.Section(name[:8])
            # lief's Section.content setter is typed memoryview[int] and at
            # runtime accepts a Sequence[int] (list/memoryview/bytearray —
            # but not raw bytes). memoryview(bytes(size)) is both: a
            # zero-filled buffer of `size` bytes that satisfies the type.
            section.content = memoryview(bytes(size))
            section.characteristics = characteristics
            section.virtual_size = size

            parsed.add_section(section)
            parsed.write(str(self.binary_path))

            added = parsed.get_section(name[:8])
            if added is None:
                logger.error(f"PE section '{name}' not found after adding")
                return None

            vaddr: int = added.virtual_address
            logger.info(f"Added PE section '{name}' ({size} bytes) at vaddr 0x{vaddr:x}")
            return vaddr

        except Exception as e:
            logger.error(f"Failed to add PE section '{name}': {e}")
            return None

    def refresh_headers(self) -> bool:
        """Refresh PE headers after mutation."""
        return repair_refresh_headers(self)

    def fix_imports(self) -> tuple[bool, list[str]]:
        """Fix import table after mutation."""
        return repair_fix_imports(self)

    def fix_exports(self) -> tuple[bool, list[str]]:
        """Fix export table after mutation."""
        return repair_fix_exports(self)

    def fix_resources(self) -> tuple[bool, list[str]]:
        """Fix resource section after mutation."""
        return repair_fix_resources(self)

    def full_repair(self) -> tuple[bool, list[str]]:
        """Full PE repair after mutation."""
        return repair_full_repair(self)
