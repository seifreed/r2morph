"""
PE (Portable Executable) format specific handling.
"""

import logging
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import lief
except Exception:  # pragma: no cover - optional dependency
    lief = None

class PEHandler:
    """
    Handles PE-specific operations.

    - Checksum fixes
    - Section manipulation
    - Import table updates
    - Resource preservation
    """

    def __init__(self, binary_path: Path):
        """
        Initialize PE handler.

        Args:
            binary_path: Path to PE file
        """
        self.binary_path = binary_path

    def _parse_lief(self):
        if lief is None:
            return None
        try:
            binary = lief.parse(str(self.binary_path))
            if isinstance(binary, lief.PE.Binary):
                return binary
            return None
        except Exception as e:
            logger.error(f"Failed to parse PE with LIEF: {e}")
            return None

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

    def fix_checksum(self) -> bool:
        """
        Recalculate and fix PE checksum.

        Returns:
            True if successful
        """
        logger.info("Fixing PE checksum")

        try:
            with open(self.binary_path, "r+b") as f:
                f.seek(0x3C)
                pe_offset = int.from_bytes(f.read(4), "little")

                checksum_offset = pe_offset + 0x58

                checksum = self._calculate_checksum()

                f.seek(checksum_offset)
                f.write(checksum.to_bytes(4, "little"))

            logger.info(f"Updated PE checksum to 0x{checksum:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to fix checksum: {e}")
            return False

    def _calculate_checksum(self) -> int:
        """
        Calculate PE checksum.

        Returns:
            Checksum value
        """
        with open(self.binary_path, "rb") as f:
            data = f.read()

        checksum = sum(data) % (2**32)
        return checksum

    def get_sections(self) -> list:
        """
        Get PE sections.

        Returns:
            List of section dicts
        """
        logger.debug("Getting PE sections")
        binary = self._parse_lief()
        if binary is None:
            try:
                sections: list[dict] = []
                with open(self.binary_path, "rb") as f:
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
                    (
                        _machine,
                        num_sections,
                        _timestamp,
                        _ptr_symbols,
                        _num_symbols,
                        size_optional,
                        _characteristics,
                    ) = struct.unpack("<HHIIIHH", coff_header)
                    f.seek(size_optional, 1)
                    for _ in range(num_sections):
                        section = f.read(40)
                        if len(section) != 40:
                            break
                        name = section[0:8].split(b"\x00", 1)[0].decode(
                            "ascii", errors="ignore"
                        )
                        (
                            virtual_size,
                            virtual_address,
                            raw_size,
                            raw_ptr,
                        ) = struct.unpack("<IIII", section[8:24])
                        sections.append(
                            {
                                "name": name,
                                "virtual_address": virtual_address,
                                "size": max(virtual_size, raw_size),
                                "offset": raw_ptr,
                            }
                        )
                return sections
            except Exception as e:
                logger.error(f"Failed to parse PE sections fallback: {e}")
                return []
        sections: list[dict] = []
        for section in binary.sections:
            sections.append(
                {
                    "name": section.name,
                    "virtual_address": section.virtual_address,
                    "size": section.size,
                    "offset": section.offset,
                }
            )
        return sections

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
        logger.info(f"Would add PE section '{name}' ({size} bytes)")
        return None
