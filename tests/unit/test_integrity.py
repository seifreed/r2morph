"""
Tests for binary integrity validation.

Covers:
- ELF integrity validation and repair
- Mach-O integrity validation and repair
- PE integrity validation and repair
- Platform-specific integrity checks
"""

from pathlib import Path
from shutil import copyfile
from typing import Any

from r2morph.validation.integrity import BinaryIntegrityValidator, validate_binary_integrity


class _Handler:
    def __init__(self) -> None:
        self.is_elf_value = True
        self.is_macho_value = True
        self.sections: list[dict[str, Any]] = []
        self.segments: list[dict[str, Any]] = []
        self.entry_point: int | None = None
        self.load_commands: list[dict[str, Any]] = []
        self.validation_result: tuple[bool, Any] = (True, [])
        self.repair_result: bool | tuple[bool, list[str]] = True

    def is_elf(self) -> bool:
        return self.is_elf_value

    def is_macho(self) -> bool:
        return self.is_macho_value

    def get_sections(self) -> list[dict[str, Any]]:
        return self.sections

    def get_segments(self) -> list[dict[str, Any]]:
        return self.segments

    def get_entry_point(self) -> int | None:
        return self.entry_point

    def get_load_commands(self) -> list[dict[str, Any]]:
        return self.load_commands

    def validate_integrity(self) -> tuple[bool, Any]:
        return self.validation_result

    def repair_integrity(self) -> bool | tuple[bool, list[str]]:
        return self.repair_result

    def mark_executable(self) -> None:
        return None

    def refresh_headers(self) -> None:
        return None


class TestBinaryIntegrityValidatorFormatDetection:
    """Test format detection."""

    def test_detect_elf(self, tmp_path):
        """Detect ELF format."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        validator = BinaryIntegrityValidator(elf_path)
        assert validator._format == "elf"

    def test_detect_macho_64(self, tmp_path):
        """Detect Mach-O 64-bit format."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        validator = BinaryIntegrityValidator(macho_path)
        assert validator._format == "macho"

    def test_detect_macho_32(self, tmp_path):
        """Detect Mach-O 32-bit format."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)

        validator = BinaryIntegrityValidator(macho_path)
        assert validator._format == "macho"

    def test_detect_pe(self, tmp_path):
        """Detect PE format."""
        pe_path = tmp_path / "test.exe"
        pe_data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 100
        pe_path.write_bytes(pe_data)

        validator = BinaryIntegrityValidator(pe_path)
        assert validator._format == "pe"

    def test_detect_unknown(self, tmp_path):
        """Detect unknown format."""
        unknown_path = tmp_path / "test.bin"
        unknown_path.write_bytes(b"UNKNOWN" + b"\x00" * 100)

        validator = BinaryIntegrityValidator(unknown_path)
        assert validator._format == "unknown"


class TestELFIntegrity:
    """Test ELF integrity validation and repair."""

    def test_valid_elf(self, tmp_path):
        """Validate a valid ELF binary."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        handler = _Handler()
        handler.is_elf_value = True
        handler.sections = [
            {"name": ".text", "virtual_address": 0x1000, "size": 0x1000},
            {"name": ".data", "virtual_address": 0x2000, "size": 0x1000},
        ]
        handler.segments = [
            {"virtual_address": 0x1000, "virtual_size": 0x2000, "flags": 5},
        ]
        handler.entry_point = 0x1000

        validator = BinaryIntegrityValidator(elf_path)
        validator._format = "elf"
        validator._handler = handler

        is_valid, issues = validator.validate()
        assert is_valid
        assert len(issues) == 0

    def test_elf_missing_sections(self, tmp_path):
        """Validate ELF with missing sections."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        handler = _Handler()
        handler.is_elf_value = True
        handler.sections = []
        handler.segments = [
            {"virtual_address": 0x1000, "virtual_size": 0x2000, "flags": 5},
        ]
        handler.entry_point = 0x1000

        validator = BinaryIntegrityValidator(elf_path)
        validator._format = "elf"
        validator._handler = handler

        is_valid, issues = validator.validate()
        assert not is_valid
        assert any("No sections" in i for i in issues)

    def test_elf_missing_required_sections(self, tmp_path):
        """Validate ELF missing required sections."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        handler = _Handler()
        handler.is_elf_value = True
        handler.sections = [
            {"name": ".rodata", "virtual_address": 0x1000, "size": 0x1000},
        ]
        handler.segments = [
            {"virtual_address": 0x1000, "virtual_size": 0x2000, "flags": 5},
        ]
        handler.entry_point = 0x1000

        validator = BinaryIntegrityValidator(elf_path)
        validator._format = "elf"
        validator._handler = handler

        is_valid, issues = validator.validate()
        assert not is_valid
        assert any(".text" in i for i in issues)

    def test_elf_wx_segment(self, tmp_path):
        """Validate ELF with writable and executable segment."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        handler = _Handler()
        handler.is_elf_value = True
        handler.sections = [
            {"name": ".text", "virtual_address": 0x1000, "size": 0x1000},
            {"name": ".data", "virtual_address": 0x2000, "size": 0x1000},
        ]
        handler.segments = [
            {"virtual_address": 0x1000, "virtual_size": 0x2000, "flags": 0x3},  # WX
        ]
        handler.entry_point = 0x1000

        validator = BinaryIntegrityValidator(elf_path)
        validator._format = "elf"
        validator._handler = handler

        _is_valid, issues = validator.validate()
        assert any("writable and executable" in i.lower() for i in issues)


class TestMachOIntegrity:
    """Test Mach-O integrity validation and repair."""

    def test_valid_macho(self, tmp_path):
        """Validate a valid Mach-O binary."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        handler = _Handler()
        handler.is_macho_value = True
        handler.validation_result = (True, "")
        handler.segments = [
            {"name": "__TEXT", "virtual_address": 0x1000, "virtual_size": 0x1000},
            {"name": "__LINKEDIT", "virtual_address": 0x2000, "virtual_size": 0x1000},
        ]
        handler.load_commands = [{"command": "LC_SEGMENT_64"}]

        validator = BinaryIntegrityValidator(macho_path)
        validator._format = "macho"
        validator._handler = handler

        is_valid, _issues = validator.validate()
        assert is_valid

    def test_macho_missing_text_segment(self, tmp_path):
        """Validate Mach-O missing __TEXT segment."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        handler = _Handler()
        handler.is_macho_value = True
        handler.validation_result = (True, "")
        handler.segments = [
            {"name": "__DATA", "virtual_address": 0x1000, "virtual_size": 0x1000},
        ]
        handler.load_commands = [{"command": "LC_SEGMENT_64"}]

        validator = BinaryIntegrityValidator(macho_path)
        validator._format = "macho"
        validator._handler = handler

        _is_valid, issues = validator.validate()
        assert any("__TEXT" in i for i in issues)

    def test_macho_repair(self, tmp_path):
        """Test Mach-O repair."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        handler = _Handler()
        handler.repair_result = True

        validator = BinaryIntegrityValidator(macho_path)
        validator._format = "macho"
        validator._handler = handler

        success, repairs = validator.repair()
        assert success
        assert "Repaired Mach-O signature" in repairs


class TestPEIntegrity:
    """Test PE integrity validation and repair."""

    def test_valid_pe(self, tmp_path):
        """Validate a valid PE binary."""
        pe_path = tmp_path / "test.exe"
        pe_data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 100
        pe_path.write_bytes(pe_data)

        handler = _Handler()
        handler.validation_result = (True, [])

        validator = BinaryIntegrityValidator(pe_path)
        validator._format = "pe"
        validator._handler = handler

        is_valid, _issues = validator.validate()
        assert is_valid

    def test_pe_checksum_mismatch(self, tmp_path):
        """Validate PE with checksum mismatch."""
        pe_path = tmp_path / "test.exe"
        pe_data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 100
        pe_path.write_bytes(pe_data)

        handler = _Handler()
        handler.validation_result = (False, ["Checksum mismatch"])

        validator = BinaryIntegrityValidator(pe_path)
        validator._format = "pe"
        validator._handler = handler

        is_valid, issues = validator.validate()
        assert not is_valid
        assert any("Checksum" in i for i in issues)

    def test_pe_repair(self, tmp_path):
        """Test PE repair."""
        pe_path = tmp_path / "test.exe"
        pe_data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 100
        pe_path.write_bytes(pe_data)

        handler = _Handler()
        handler.repair_result = (True, ["Checksum updated"])

        validator = BinaryIntegrityValidator(pe_path)
        validator._format = "pe"
        validator._handler = handler

        success, repairs = validator.repair()
        assert success
        assert "Checksum updated" in repairs


class TestValidateBinaryIntegrity:
    """Test the convenience function."""

    def test_validate_without_repair_returns_detected_issues(self, tmp_path):
        elf_path = tmp_path / "test.elf"
        copyfile(Path(__file__).parents[2] / "dataset" / "elf_x86_64", elf_path)

        result = validate_binary_integrity(elf_path, repair=False)

        assert result == (
            False,
            [
                "Missing required section: .data",
                "Entry point 0x201120 not in any executable segment",
            ],
            [],
        )

    def test_validate_with_repair_revalidates_binary(self, tmp_path):
        elf_path = tmp_path / "test.elf"
        copyfile(Path(__file__).parents[2] / "dataset" / "elf_x86_64", elf_path)

        result = validate_binary_integrity(elf_path, repair=True)

        assert result == (
            False,
            [
                "Missing required section: .data",
                "Entry point 0x201120 not in any executable segment",
            ],
            [],
        )
