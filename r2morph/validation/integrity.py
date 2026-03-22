"""
Binary integrity validation for post-mutation checks and repair.

This module provides platform-agnostic integrity validation and
automatic repair for ELF, Mach-O, and PE binaries.
"""

import logging
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class BinaryIntegrityValidator:
    """
    Validates and repairs binary integrity after mutations.

    Platform-specific handling:
    - ELF: Section/segment consistency, entry point validity
    - Mach-O: LC_* commands, code signature, load commands
    - PE: Checksum, relocation directories, import/export tables
    """

    def __init__(self, binary_path: Path, binary: Binary | None = None) -> None:
        """
        Initialize binary integrity validator.

        Args:
            binary_path: Path to the binary file
            binary: Optional Binary instance for radare2-based checks
        """
        self.binary_path = binary_path
        self.binary = binary
        self._handler: Any = None
        self._format: str | None = None
        self._detect_format()

    def _detect_format(self) -> str:
        """Detect the binary format."""
        try:
            with open(self.binary_path, "rb") as f:
                magic = f.read(4)

            if magic[:2] == b"MZ":
                self._format = "pe"
                return "pe"

            if magic in (b"\x7fELF", b"\x7f\x45\x4c\x46"):
                self._format = "elf"
                return "elf"

            if magic in (
                b"\xfe\xed\xfa\xce",
                b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf",
                b"\xcf\xfa\xed\xfe",
            ):
                self._format = "macho"
                return "macho"

            if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                self._format = "fat_macho"
                return "fat_macho"

            self._format = "unknown"
            return "unknown"
        except Exception:
            self._format = "unknown"
            return "unknown"

    def _get_handler(self) -> Any | None:
        """Get the platform-specific handler."""
        if self._handler is not None:
            return self._handler

        if self._format == "elf":
            from r2morph.platform.elf_handler import ELFHandler

            self._handler = ELFHandler(self.binary_path)
        elif self._format in ("macho", "fat_macho"):
            from r2morph.platform.macho_handler import MachOHandler

            self._handler = MachOHandler(self.binary_path)
        elif self._format == "pe":
            from r2morph.platform.pe_handler import PEHandler

            self._handler = PEHandler(self.binary_path)

        return self._handler

    def validate(self) -> tuple[bool, list[str]]:
        """
        Validate binary integrity.

        Returns:
            (is_valid, list of issues)
        """
        issues: list[str] = []

        if self._format == "unknown":
            issues.append("Unknown binary format")
            return False, issues

        handler = self._get_handler()
        if handler is None:
            issues.append("No handler available for format")
            return False, issues

        if self._format == "elf":
            return self._validate_elf(handler)
        elif self._format in ("macho", "fat_macho"):
            return self._validate_macho(handler)
        elif self._format == "pe":
            return self._validate_pe(handler)

        return True, []

    def _validate_elf(self, handler: Any) -> tuple[bool, list[str]]:
        """Validate ELF binary integrity."""
        issues: list[str] = []

        try:
            if not handler.is_elf():
                issues.append("Not a valid ELF binary")
                return False, issues

            sections = handler.get_sections()
            if not sections:
                issues.append("No sections found in ELF")

            segments = handler.get_segments()
            if not segments:
                issues.append("No segments found in ELF")

            section_names = {s.get("name", "") for s in sections}

            required_sections = [".text", ".data"]
            for req in required_sections:
                if req not in section_names:
                    issues.append(f"Missing required section: {req}")

            for segment in segments:
                flags = segment.get("flags", 0)
                p_flags_executable = 0x1
                p_flags_writable = 0x2

                if flags & p_flags_executable and flags & p_flags_writable:
                    issues.append(f"Segment at 0x{segment.get('virtual_address', 0):x} is both writable and executable")

            entry_point = handler.get_entry_point()
            if entry_point is not None:
                found_entry = False
                for seg in segments:
                    va = seg.get("virtual_address", 0)
                    size = seg.get("virtual_size", seg.get("memsz", 0))
                    if va <= entry_point < va + size:
                        found_entry = True
                        break
                if not found_entry:
                    issues.append(f"Entry point 0x{entry_point:x} not in any executable segment")

        except Exception as e:
            issues.append(f"ELF validation error: {e}")

        return len(issues) == 0, issues

    def _validate_macho(self, handler: Any) -> tuple[bool, list[str]]:
        """Validate Mach-O binary integrity."""
        issues: list[str] = []

        try:
            if not handler.is_macho():
                issues.append("Not a valid Mach-O binary")
                return False, issues

            ok, msg = handler.validate_integrity()
            if not ok:
                issues.append(f"Mach-O integrity issue: {msg}")

            segments = handler.get_segments()
            if not segments:
                issues.append("No segments found in Mach-O")

            load_commands = handler.get_load_commands()
            if not load_commands:
                issues.append("No load commands found")

            has_text = False
            has_linkedit = False
            for seg in segments:
                name = seg.get("name", "")
                if name == "__TEXT":
                    has_text = True
                elif name == "__LINKEDIT":
                    has_linkedit = True

            if not has_text:
                issues.append("Missing __TEXT segment")
            if not has_linkedit:
                issues.append("Missing __LINKEDIT segment")

            for seg in segments:
                for other in segments:
                    if seg is other:
                        continue
                    va1 = seg.get("virtual_address", 0)
                    size1 = seg.get("virtual_size", 0)
                    va2 = other.get("virtual_address", 0)
                    size2 = other.get("virtual_size", 0)

                    if va1 < va2 + size2 and va1 + size1 > va2:
                        issues.append(f"Overlapping segments: {seg.get('name')} and {other.get('name')}")

        except Exception as e:
            issues.append(f"Mach-O validation error: {e}")

        return len(issues) == 0, issues

    def _validate_pe(self, handler: Any) -> tuple[bool, list[str]]:
        """Validate PE binary integrity."""
        result: tuple[bool, list[str]] = handler.validate_integrity()
        return result

    def repair(self) -> tuple[bool, list[str]]:
        """
        Repair binary integrity issues.

        Returns:
            (success, list of repairs made)
        """

        if self._format == "unknown":
            return False, ["Unknown binary format"]

        handler = self._get_handler()
        if handler is None:
            return False, ["No handler available"]

        if self._format == "elf":
            return self._repair_elf(handler)
        elif self._format in ("macho", "fat_macho"):
            return self._repair_macho(handler)
        elif self._format == "pe":
            return self._repair_pe(handler)

        return False, ["No repair logic for format"]

    def _repair_elf(self, handler: Any) -> tuple[bool, list[str]]:
        """Repair ELF binary integrity."""
        repairs: list[str] = []

        try:
            if hasattr(handler, "fix_section_headers"):
                if handler.fix_section_headers():
                    repairs.append("Fixed section headers")

            if hasattr(handler, "fix_program_headers"):
                if handler.fix_program_headers():
                    repairs.append("Fixed program headers")

            logger.info(f"ELF repairs: {repairs}")
            return True, repairs

        except Exception as e:
            logger.error(f"ELF repair error: {e}")
            repairs.append(f"Error: {e}")
            return False, repairs

    def _repair_macho(self, handler: Any) -> tuple[bool, list[str]]:
        """Repair Mach-O binary integrity."""
        repairs: list[str] = []

        try:
            if hasattr(handler, "repair_integrity"):
                success = handler.repair_integrity()
                if success:
                    repairs.append("Repaired Mach-O signature")
                else:
                    repairs.append("Signature repair attempted")

            if hasattr(handler, "mark_executable"):
                try:
                    handler.mark_executable()
                    repairs.append("Marked executable")
                except Exception:
                    pass

            logger.info(f"Mach-O repairs: {repairs}")
            return True, repairs

        except Exception as e:
            logger.error(f"Mach-O repair error: {e}")
            repairs.append(f"Error: {e}")
            return False, repairs

    def _repair_pe(self, handler: Any) -> tuple[bool, list[str]]:
        """Repair PE binary integrity."""
        repairs: list[str] = []

        try:
            success, repairs_made = handler.repair_integrity()
            repairs.extend(repairs_made)

            if hasattr(handler, "refresh_headers"):
                handler.refresh_headers()
                repairs.append("Refreshed PE headers")

            logger.info(f"PE repairs: {repairs}")
            return success, repairs

        except Exception as e:
            logger.error(f"PE repair error: {e}")
            repairs.append(f"Error: {e}")
            return False, repairs

    def validate_and_repair(self) -> tuple[bool, list[str], list[str]]:
        """
        Validate and optionally repair binary integrity.

        Returns:
            (is_valid, issues, repairs_made)
        """
        is_valid, issues = self.validate()

        if is_valid:
            return True, [], []

        success, repairs = self.repair()

        if success:
            is_valid, remaining_issues = self.validate()
            return is_valid, remaining_issues, repairs

        return False, issues, repairs


def validate_binary_integrity(
    binary_path: Path, binary: Binary | None = None, repair: bool = True
) -> tuple[bool, list[str], list[str]]:
    """
    Convenience function for binary integrity validation.

    Args:
        binary_path: Path to the binary
        binary: Optional Binary instance
        repair: Whether to attempt repairs

    Returns:
        (is_valid, issues, repairs_made)
    """
    validator = BinaryIntegrityValidator(binary_path, binary)

    if repair:
        return validator.validate_and_repair()

    is_valid, issues = validator.validate()
    return is_valid, issues, []
