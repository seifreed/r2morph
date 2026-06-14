"""
Binary integrity validation for post-mutation checks and repair.

This module provides platform-agnostic integrity validation and
automatic repair for ELF, Mach-O, and PE binaries.
"""

import logging
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.integrity_repair_helpers import (
    repair_elf_integrity,
    repair_macho_integrity,
    repair_pe_integrity,
)
from r2morph.validation.integrity_validation_helpers import (
    detect_binary_format,
    validate_elf_integrity,
    validate_macho_integrity,
    validate_pe_integrity,
)

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
        self._format = detect_binary_format(self.binary_path)
        return self._format

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
        return validate_elf_integrity(handler)

    def _validate_macho(self, handler: Any) -> tuple[bool, list[str]]:
        """Validate Mach-O binary integrity."""
        return validate_macho_integrity(handler)

    def _validate_pe(self, handler: Any) -> tuple[bool, list[str]]:
        """Validate PE binary integrity."""
        return validate_pe_integrity(handler)

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
            return repair_elf_integrity(handler)
        elif self._format in ("macho", "fat_macho"):
            return repair_macho_integrity(handler)
        elif self._format == "pe":
            return repair_pe_integrity(handler)

        return False, ["No repair logic for format"]

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
