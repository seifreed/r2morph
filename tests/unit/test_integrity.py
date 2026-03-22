"""
Tests for binary integrity validation.

Covers:
- ELF integrity validation and repair
- Mach-O integrity validation and repair
- PE integrity validation and repair
- Platform-specific integrity checks
"""

from unittest.mock import MagicMock, patch

from r2morph.validation.integrity import BinaryIntegrityValidator, validate_binary_integrity


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

        mock_handler = MagicMock()
        mock_handler.is_elf.return_value = True
        mock_handler.get_sections.return_value = [
            {"name": ".text", "virtual_address": 0x1000, "size": 0x1000},
            {"name": ".data", "virtual_address": 0x2000, "size": 0x1000},
        ]
        mock_handler.get_segments.return_value = [
            {"virtual_address": 0x1000, "virtual_size": 0x2000, "flags": 5},
        ]
        mock_handler.get_entry_point.return_value = 0x1000

        with patch("r2morph.platform.elf_handler.ELFHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(elf_path)
            validator._format = "elf"
            validator._handler = mock_handler

            is_valid, issues = validator.validate()
            assert is_valid
            assert len(issues) == 0

    def test_elf_missing_sections(self, tmp_path):
        """Validate ELF with missing sections."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_handler = MagicMock()
        mock_handler.is_elf.return_value = True
        mock_handler.get_sections.return_value = []
        mock_handler.get_segments.return_value = [
            {"virtual_address": 0x1000, "virtual_size": 0x2000, "flags": 5},
        ]
        mock_handler.get_entry_point.return_value = 0x1000

        with patch("r2morph.platform.elf_handler.ELFHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(elf_path)
            validator._format = "elf"
            validator._handler = mock_handler

            is_valid, issues = validator.validate()
            assert not is_valid
            assert any("No sections" in i for i in issues)

    def test_elf_missing_required_sections(self, tmp_path):
        """Validate ELF missing required sections."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_handler = MagicMock()
        mock_handler.is_elf.return_value = True
        mock_handler.get_sections.return_value = [
            {"name": ".rodata", "virtual_address": 0x1000, "size": 0x1000},
        ]
        mock_handler.get_segments.return_value = [
            {"virtual_address": 0x1000, "virtual_size": 0x2000, "flags": 5},
        ]
        mock_handler.get_entry_point.return_value = 0x1000

        with patch("r2morph.platform.elf_handler.ELFHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(elf_path)
            validator._format = "elf"
            validator._handler = mock_handler

            is_valid, issues = validator.validate()
            assert not is_valid
            assert any(".text" in i for i in issues)

    def test_elf_wx_segment(self, tmp_path):
        """Validate ELF with writable and executable segment."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_handler = MagicMock()
        mock_handler.is_elf.return_value = True
        mock_handler.get_sections.return_value = [
            {"name": ".text", "virtual_address": 0x1000, "size": 0x1000},
            {"name": ".data", "virtual_address": 0x2000, "size": 0x1000},
        ]
        mock_handler.get_segments.return_value = [
            {"virtual_address": 0x1000, "virtual_size": 0x2000, "flags": 0x3},  # WX
        ]
        mock_handler.get_entry_point.return_value = 0x1000

        with patch("r2morph.platform.elf_handler.ELFHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(elf_path)
            validator._format = "elf"
            validator._handler = mock_handler

            is_valid, issues = validator.validate()
            assert any("writable and executable" in i.lower() for i in issues)


class TestMachOIntegrity:
    """Test Mach-O integrity validation and repair."""

    def test_valid_macho(self, tmp_path):
        """Validate a valid Mach-O binary."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        mock_handler = MagicMock()
        mock_handler.is_macho.return_value = True
        mock_handler.validate_integrity.return_value = (True, "")
        mock_handler.get_segments.return_value = [
            {"name": "__TEXT", "virtual_address": 0x1000, "virtual_size": 0x1000},
            {"name": "__LINKEDIT", "virtual_address": 0x2000, "virtual_size": 0x1000},
        ]
        mock_handler.get_load_commands.return_value = [{"command": "LC_SEGMENT_64"}]

        with patch("r2morph.platform.macho_handler.MachOHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(macho_path)
            validator._format = "macho"
            validator._handler = mock_handler

            is_valid, issues = validator.validate()
            assert is_valid

    def test_macho_missing_text_segment(self, tmp_path):
        """Validate Mach-O missing __TEXT segment."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        mock_handler = MagicMock()
        mock_handler.is_macho.return_value = True
        mock_handler.validate_integrity.return_value = (True, "")
        mock_handler.get_segments.return_value = [
            {"name": "__DATA", "virtual_address": 0x1000, "virtual_size": 0x1000},
        ]
        mock_handler.get_load_commands.return_value = [{"command": "LC_SEGMENT_64"}]

        with patch("r2morph.platform.macho_handler.MachOHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(macho_path)
            validator._format = "macho"
            validator._handler = mock_handler

            is_valid, issues = validator.validate()
            assert any("__TEXT" in i for i in issues)

    def test_macho_repair(self, tmp_path):
        """Test Mach-O repair."""
        macho_path = tmp_path / "test.macho"
        macho_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        mock_handler = MagicMock()
        mock_handler.repair_integrity.return_value = True

        with patch("r2morph.platform.macho_handler.MachOHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(macho_path)
            validator._format = "macho"
            validator._handler = mock_handler

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

        mock_handler = MagicMock()
        mock_handler.validate_integrity.return_value = (True, [])

        with patch("r2morph.platform.pe_handler.PEHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(pe_path)
            validator._format = "pe"
            validator._handler = mock_handler

            is_valid, issues = validator.validate()
            assert is_valid

    def test_pe_checksum_mismatch(self, tmp_path):
        """Validate PE with checksum mismatch."""
        pe_path = tmp_path / "test.exe"
        pe_data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 100
        pe_path.write_bytes(pe_data)

        mock_handler = MagicMock()
        mock_handler.validate_integrity.return_value = (False, ["Checksum mismatch"])

        with patch("r2morph.platform.pe_handler.PEHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(pe_path)
            validator._format = "pe"
            validator._handler = mock_handler

            is_valid, issues = validator.validate()
            assert not is_valid
            assert any("Checksum" in i for i in issues)

    def test_pe_repair(self, tmp_path):
        """Test PE repair."""
        pe_path = tmp_path / "test.exe"
        pe_data = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 100
        pe_path.write_bytes(pe_data)

        mock_handler = MagicMock()
        mock_handler.repair_integrity.return_value = (True, ["Checksum updated"])

        with patch("r2morph.platform.pe_handler.PEHandler", return_value=mock_handler):
            validator = BinaryIntegrityValidator(pe_path)
            validator._format = "pe"
            validator._handler = mock_handler

            success, repairs = validator.repair()
            assert success
            assert "Checksum updated" in repairs


class TestValidateBinaryIntegrity:
    """Test the convenience function."""

    def test_validate_without_repair(self, tmp_path):
        """Validate without repair."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_validator = MagicMock()
        mock_validator.validate.return_value = (True, [])

        with patch("r2morph.validation.integrity.BinaryIntegrityValidator", return_value=mock_validator):
            is_valid, issues, repairs = validate_binary_integrity(elf_path, repair=False)
            assert is_valid
            assert len(issues) == 0
            assert len(repairs) == 0

    def test_validate_with_repair(self, tmp_path):
        """Validate with repair."""
        elf_path = tmp_path / "test.elf"
        elf_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_validator = MagicMock()
        mock_validator.validate_and_repair.return_value = (True, [], ["Checksum fixed"])

        with patch("r2morph.validation.integrity.BinaryIntegrityValidator", return_value=mock_validator):
            is_valid, issues, repairs = validate_binary_integrity(elf_path, repair=True)
            assert is_valid
            assert len(repairs) == 1
            assert "Checksum fixed" in repairs
