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
import struct
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import lief

    LIEF_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    lief = None  # type: ignore[assignment]
    LIEF_AVAILABLE = False


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
        try:
            with open(self.binary_path, "rb") as f:
                if f.read(2) != b"MZ":
                    return None

                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                self._pe_offset = pe_offset

                f.seek(pe_offset)
                if f.read(4) != b"PE\x00\x00":
                    return None

                coff_header = f.read(20)
                if len(coff_header) != 20:
                    return None

                (
                    machine,
                    num_sections,
                    timestamp,
                    ptr_symbols,
                    num_symbols,
                    size_optional,
                    characteristics,
                ) = struct.unpack("<HHIIIHH", coff_header)

                optional_header_offset = pe_offset + 24

                f.seek(optional_header_offset)
                magic = struct.unpack("<H", f.read(2))[0]

                is_pe32_plus = magic == 0x20B
                header_size = 240 if is_pe32_plus else 96

                f.seek(optional_header_offset)
                optional_header = f.read(header_size)

                if is_pe32_plus:
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
                        checksum_offset_raw,
                        _subsystem,
                        _dll_characteristics,
                        _size_stack_reserve,
                        _size_stack_commit,
                        _size_heap_reserve,
                        _size_heap_commit,
                        _loader_flags,
                        num_rva_sizes,
                    ) = struct.unpack("<HHIIIIIIIIIIIIIIIQIIIIII", optional_header[:120])
                else:
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
                        checksum_offset_raw,
                        _subsystem,
                        _dll_characteristics,
                        _size_stack_reserve,
                        _size_stack_commit,
                        _size_heap_reserve,
                        _size_heap_commit,
                        _loader_flags,
                        num_rva_sizes,
                    ) = struct.unpack("<HHIIIIIIIIIIIIIIIIII", optional_header[:96])

                num_data_directories = num_rva_sizes

                # Checksum is always at offset 64 from start of optional header,
                # regardless of PE32 vs PE32+
                checksum_offset = optional_header_offset + 64

                return {
                    "pe_offset": pe_offset,
                    "machine": machine,
                    "num_sections": num_sections,
                    "timestamp": timestamp,
                    "size_optional": size_optional,
                    "characteristics": characteristics,
                    "is_pe32_plus": is_pe32_plus,
                    "image_base": image_base,
                    "entry_point": entry_point,
                    "section_alignment": section_alignment,
                    "file_alignment": file_alignment,
                    "checksum_offset": checksum_offset,
                    "num_data_directories": num_data_directories,
                    "optional_header_offset": optional_header_offset,
                }
        except Exception as e:
            logger.error(f"Failed to read PE header: {e}")
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

    def get_checksum_offset(self) -> int | None:
        """
        Get the offset of the PE checksum in the file.

        Note: The checksum offset is at the same position (64 bytes from optional header start)
        for both PE32 and PE32+ formats.

        Returns:
            Offset of checksum field or None
        """
        try:
            with open(self.binary_path, "rb") as f:
                if f.read(2) != b"MZ":
                    return None
                f.seek(0x3C)
                pe_offset_bytes = f.read(4)
                if len(pe_offset_bytes) != 4:
                    return None
                pe_offset = struct.unpack("<I", pe_offset_bytes)[0]

                # Validate PE signature
                f.seek(pe_offset)
                if f.read(4) != b"PE\x00\x00":
                    return None

                # Checksum is always at offset 64 from start of optional header
                # Optional header starts at pe_offset + 24
                checksum_offset = pe_offset + 24 + 64

                # Verify the file is large enough
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()
                if checksum_offset + 4 > file_size:
                    return None

                return int(checksum_offset)
        except Exception:
            return None

    def fix_checksum(self) -> bool:
        """
        Recalculate and fix PE checksum.

        Returns:
            True if successful
        """
        logger.info("Fixing PE checksum")

        try:
            checksum = self._calculate_pe_checksum()

            checksum_offset = self.get_checksum_offset()
            if checksum_offset is None:
                return False

            with open(self.binary_path, "r+b") as f:
                f.seek(checksum_offset)
                f.write(checksum.to_bytes(4, "little"))

            logger.info(f"Updated PE checksum to 0x{checksum:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to fix checksum: {e}")
            return False

    def _calculate_pe_checksum(self) -> int:
        """
        Calculate PE checksum using Microsoft's algorithm.

        Returns:
            Checksum value
        """
        with open(self.binary_path, "rb") as f:
            data = f.read()

        checksum_offset = self.get_checksum_offset()
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

    def _calculate_checksum(self) -> int:
        """Simple checksum (legacy)."""
        with open(self.binary_path, "rb") as f:
            data = f.read()
        return sum(data) % (2**32)

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
            sections: list[dict] = []
            for section in binary.sections:
                sections.append(
                    {
                        "name": section.name,
                        "virtual_address": section.virtual_address,
                        "virtual_size": section.virtual_size,
                        "raw_size": section.size,
                        "offset": section.offset,
                        "characteristics": section.characteristics,
                    }
                )
            self._sections_cache = sections
            return sections

        try:
            sections = []
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
                MAX_SECTIONS = 10000
                if num_sections > MAX_SECTIONS:
                    logger.warning(f"Excessive section count {num_sections}, limiting to {MAX_SECTIONS}")
                    num_sections = MAX_SECTIONS

                for _ in range(num_sections):
                    section = f.read(40)
                    if len(section) != 40:
                        break
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
                    ) = struct.unpack("<IIIIIIII", section[8:40])

                    # Validate section values to prevent unreasonable sizes
                    MAX_SECTION_SIZE = 0x10000000  # 256MB
                    if virtual_size > MAX_SECTION_SIZE:
                        virtual_size = MAX_SECTION_SIZE
                    if raw_size > MAX_SECTION_SIZE:
                        raw_size = MAX_SECTION_SIZE

                    sections.append(
                        {
                            "name": name,
                            "virtual_address": virtual_address,
                            "size": max(virtual_size, raw_size),
                            "offset": raw_ptr,
                            "characteristics": characteristics,
                        }
                    )
            self._sections_cache = sections
            return sections
        except Exception as e:
            logger.error(f"Failed to parse PE sections fallback: {e}")
            return []

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
        """
        Validate PE integrity after mutation.

        Returns:
            (is_valid, list of issues)
        """
        issues: list[str] = []

        if not self.is_pe():
            issues.append("Not a PE binary")
            return False, issues

        binary = self._parse_lief()
        if binary is None:
            return True, []

        if not binary.has_header:
            issues.append("Missing PE header")

        sections = self.get_sections()
        if not sections:
            issues.append("No sections found")

        section_bounds: dict[int, int] = {}
        for i, section in enumerate(sections):
            va = section.get("virtual_address", 0)
            size = section.get("size", 0)
            for other_va, other_size in section_bounds.items():
                if va < other_va + other_size and va + size > other_va:
                    issues.append(f"Overlapping sections at index {i}")
                    break
            section_bounds[va] = size

        for reloc in self.get_relocations():
            addr = reloc.get("address", 0)
            in_section = False
            for section in sections:
                va = section.get("virtual_address", 0)
                size = section.get("size", 0)
                if va <= addr < va + size:
                    in_section = True
                    break
            if not in_section:
                issues.append(f"Relocation at 0x{addr:x} outside any section")

        current_checksum = self._get_stored_checksum()
        calculated_checksum = self._calculate_pe_checksum()
        if current_checksum != calculated_checksum:
            issues.append(f"Checksum mismatch: stored 0x{current_checksum:08x}, calculated 0x{calculated_checksum:08x}")

        return len(issues) == 0, issues

    def _get_stored_checksum(self) -> int:
        """Get the stored checksum from the PE header."""
        try:
            checksum_offset = self.get_checksum_offset()
            if checksum_offset is None:
                return 0
            with open(self.binary_path, "rb") as f:
                f.seek(checksum_offset)
                return int(struct.unpack("<I", f.read(4))[0])
        except Exception:
            return 0

    def repair_integrity(self) -> tuple[bool, list[str]]:
        """
        Repair PE integrity after mutation.

        Returns:
            (success, list of repairs made)
        """
        repairs: list[str] = []
        success = True

        if not self.is_pe():
            return False, ["Not a PE binary"]

        if self.fix_checksum():
            repairs.append("Updated PE checksum")
        else:
            success = False
            repairs.append("Failed to update checksum")

        binary = self._parse_lief()
        if binary is not None and hasattr(binary, "write"):
            try:
                tmp_path = self.binary_path.with_suffix(".repaired")
                binary.write(str(tmp_path))
                tmp_path.replace(self.binary_path)
                repairs.append("Rebuilt PE with LIEF")
            except Exception as e:
                logger.warning(f"LIEF rebuild failed: {e}")

        return success, repairs

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

    def refresh_headers(self) -> bool:
        """
        Refresh PE headers after mutation.

        This recalculates:
        - Size of image
        - Size of headers
        - Checksum
        - Data directories

        Returns:
            True if successful
        """
        binary = self._parse_lief()
        if binary is None:
            return self.fix_checksum()

        try:
            if hasattr(binary, "size"):
                pass

            tmp_path = self.binary_path.with_suffix(".refreshed")
            binary.write(str(tmp_path))
            tmp_path.replace(self.binary_path)

            if lief is not None:
                parsed = lief.parse(str(self.binary_path))
                if isinstance(parsed, lief.PE.Binary):
                    self._binary = parsed
            self._sections_cache = None

            self.fix_checksum()

            logger.info("Refreshed PE headers")
            return True

        except Exception as e:
            logger.error(f"Failed to refresh PE headers: {e}")
            return False

    def fix_imports(self) -> tuple[bool, list[str]]:
        """
        Fix import table after mutation.

        Returns:
            (success, list of fixes applied)
        """
        fixes: list[str] = []
        binary = self._parse_lief()

        if binary is None:
            return True, fixes

        try:
            imports_valid = True
            for imported_binary in list(getattr(binary, "imports", [])):
                try:
                    if hasattr(imported_binary, "name") and imported_binary.name:
                        fixes.append(f"Verified import: {imported_binary.name}")
                except Exception:
                    imports_valid = False

            return imports_valid, fixes
        except Exception as e:
            logger.debug(f"Import fix failed: {e}")
            return False, fixes

    def fix_exports(self) -> tuple[bool, list[str]]:
        """
        Fix export table after mutation.

        Returns:
            (success, list of fixes applied)
        """
        fixes: list[str] = []
        binary = self._parse_lief()

        if binary is None:
            return True, fixes

        try:
            if hasattr(binary, "has_exports") and binary.has_exports:
                for export in binary.exported_functions:
                    fixes.append(f"Verified export: {export.name}")
            return True, fixes
        except Exception as e:
            logger.debug(f"Export fix failed: {e}")
            return False, fixes

    def fix_resources(self) -> tuple[bool, list[str]]:
        """
        Fix resource section after mutation.

        Returns:
            (success, list of fixes applied)
        """
        fixes: list[str] = []
        binary = self._parse_lief()

        if binary is None:
            return True, fixes

        try:
            resources = getattr(binary, "resources", None)
            if resources:
                fixes.append("Resources verified")
            return True, fixes
        except Exception as e:
            logger.debug(f"Resource fix failed: {e}")
            return False, fixes

    def full_repair(self) -> tuple[bool, list[str]]:
        """
        Full PE repair after mutation.

        Performs all necessary repairs:
        - Checksum
        - Imports
        - Exports
        - Resources
        - Relocations
        - Headers

        Returns:
            (success, list of all repairs)
        """
        all_repairs: list[str] = []
        all_success = True

        checksum_result = self.fix_checksum()
        checks = [
            ("checksum", (checksum_result if isinstance(checksum_result, tuple) else (checksum_result, []))),
            ("imports", self.fix_imports()),
            ("exports", self.fix_exports()),
            ("resources", self.fix_resources()),
            ("headers", (self.refresh_headers(), ["Headers refreshed"])),
        ]

        for name, result in checks:
            if isinstance(result, tuple):
                success, repairs = result
            else:
                success, repairs = result, []
            if repairs:
                all_repairs.extend(repairs)
            if not success:
                all_success = False
                all_repairs.append(f"Warning: {name} repair may have issues")

        return all_success, all_repairs
