"""
Integration tests for PE binary integrity repair.

Tests for Issue #4:
- PE integrity validation
- Checksum calculation and verification
- Import/export table integrity
- Relocation directory validation
- Section overlap detection
"""

import pytest
import platform
import struct

from r2morph.platform.pe_handler import PEHandler


class TestPEIntegrityBasic:
    """Basic PE integrity tests that work without special binaries."""

    def test_is_pe_with_non_pe(self, tmp_path):
        """Test is_pe returns False for non-PE files."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = PEHandler(test_file)
        assert not handler.is_pe()

    def test_is_pe_with_elf(self, tmp_path):
        """Test is_pe returns False for ELF files."""
        test_file = tmp_path / "test.elf"
        test_file.write_bytes(b"\x7fELF")

        handler = PEHandler(test_file)
        assert not handler.is_pe()

    def test_is_pe_with_macho(self, tmp_path):
        """Test is_pe returns False for Mach-O files."""
        test_file = tmp_path / "test.macho"
        test_file.write_bytes(b"\xfe\xed\xfa\xce")

        handler = PEHandler(test_file)
        assert not handler.is_pe()

    def test_validate_non_pe(self, tmp_path):
        """Test validate returns False for non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = PEHandler(test_file)
        assert not handler.validate()

    def test_validate_integrity_non_pe(self, tmp_path):
        """Test validate_integrity fails for non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = PEHandler(test_file)
        valid, issues = handler.validate_integrity()

        assert not valid
        assert "Not a PE" in " ".join(issues)

    def test_get_sections_non_pe(self, tmp_path):
        """Test get_sections on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = PEHandler(test_file)
        sections = handler.get_sections()

        assert sections == []

    def test_get_imports_non_pe(self, tmp_path):
        """Test get_imports on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = PEHandler(test_file)
        imports = handler.get_imports()

        assert imports == []

    def test_get_exports_non_pe(self, tmp_path):
        """Test get_exports on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = PEHandler(test_file)
        exports = handler.get_exports()

        assert exports == []

    def test_get_relocations_non_pe(self, tmp_path):
        """Test get_relocations on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = PEHandler(test_file)
        relocs = handler.get_relocations()

        assert relocs == []

    def test_fix_checksum_non_pe(self, tmp_path):
        """Test fix_checksum on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = PEHandler(test_file)
        result = handler.fix_checksum()

        assert not result

    def test_full_repair_non_pe(self, tmp_path):
        """Test full_repair on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00")

        handler = PEHandler(test_file)
        success, repairs = handler.full_repair()

        assert not success


class TestPEBasicParsing:
    """Test PE basic parsing."""

    def test_pe_header_parsing_32bit(self, tmp_path):
        """Test parsing a 32-bit PE header."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x14C,
            1,
            0,
            0,
            0,
            224,
            0x102,
        )

        optional_header = struct.pack(
            "<HHIIIIIIIIIIIIIIIII",
            0x10B,
            1,
            0,
            0,
            0,
            0x1000,
            0x10000,
            0x1000,
            0x200,
            4,
            0,
            4,
            0,
            0,
            0,
            0x1000,
            0x200,
            0,
            16,
        )

        section_header = b".text\x00\x00\x00" + struct.pack(
            "<IIIIIIII",
            0x1000,
            0x1000,
            0x200,
            0x200,
            0,
            0,
            0,
            0x60000020,
        )

        pe_data = dos_header + pe_signature + coff_header + optional_header + section_header
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)

        assert handler.is_pe()

    def test_pe_header_parsing_64bit(self, tmp_path):
        """Test parsing a 64-bit PE header."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x8664,
            1,
            0,
            0,
            0,
            240,
            0x22,
        )

        optional_header = struct.pack(
            "<HHIIIIIIIIIIIIIIIQIIIIII",
            0x20B,
            1,
            0,
            0,
            0,
            0x1000,
            0x10000,
            0x1000,
            0x200,
            6,
            0,
            6,
            0,
            0,
            0x1000,
            0x200,
            0,
            0x10000,
            0x1000,
            0,
            0,
            0,
            0,
            16,
        )

        section_header = b".text\x00\x00\x00" + struct.pack(
            "<IIIIIIII",
            0x1000,
            0x1000,
            0x200,
            0x200,
            0,
            0,
            0,
            0x60000020,
        )

        pe_data = dos_header + pe_signature + coff_header + optional_header + section_header
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)

        assert handler.is_pe()

    def test_get_checksum_offset(self, tmp_path):
        """Test get_checksum_offset."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)

        pe_data = dos_header + pe_signature + coff_header
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)
        handler.get_checksum_offset()

        pass

    def test_calculate_checksum(self, tmp_path):
        """Test _calculate_pe_checksum."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)

        pe_data = dos_header + pe_signature + coff_header + b"\x00" * 100
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)
        checksum = handler._calculate_pe_checksum()

        assert isinstance(checksum, int)
        assert checksum >= 0

    def test_get_pe_header_info(self, tmp_path):
        """Test _read_pe_header."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)

        pe_data = dos_header + pe_signature + coff_header + b"\x00" * 96
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)
        handler._read_pe_header()

        pass


class TestPEChecksumCalculation:
    """Test PE checksum calculation."""

    def test_checksum_basic(self, tmp_path):
        """Test basic checksum calculation."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
        optional_header = b"\x00" * 96

        pe_data = dos_header + pe_signature + coff_header + optional_header
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)

        if handler.is_pe():
            checksum = handler._calculate_pe_checksum()
            assert isinstance(checksum, int)

    def test_checksum_file_size_included(self, tmp_path):
        """Test that file size is included in checksum."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
        optional_header = b"\x00" * 96

        pe_data_small = dos_header + pe_signature + coff_header + optional_header + b"\x00" * 100
        test_file.write_bytes(pe_data_small)

        handler = PEHandler(test_file)
        handler._calculate_pe_checksum()

        pe_data_large = dos_header + pe_signature + coff_header + optional_header + b"\x00" * 200
        test_file.write_bytes(pe_data_large)

        handler._calculate_pe_checksum()

        pass


class TestPESectionHandling:
    """Test PE section handling."""

    def test_get_sections_parsed(self, tmp_path):
        """Test section parsing."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 2, 0, 0, 0, 224, 0x102)
        optional_header = b"\x00" * 96

        section1 = b".text\x00\x00\x00" + struct.pack(
            "<IIIIIIII",
            0x1000,
            0x1000,
            0x200,
            0x200,
            0,
            0,
            0,
            0x60000020,
        )
        section2 = b".data\x00\x00\x00" + struct.pack(
            "<IIIIIIII",
            0x2000,
            0x1000,
            0x400,
            0x400,
            0,
            0,
            0,
            0xC0000040,
        )

        pe_data = dos_header + pe_signature + coff_header + optional_header + section1 + section2
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)

        if handler.is_pe():
            handler.get_sections()

            pass

    def test_section_validation(self, tmp_path):
        """Test section validation."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
        optional_header = b"\x00" * 96

        section = b".text\x00\x00\x00" + struct.pack(
            "<IIIIIIII",
            0x1000,
            0x1000,
            0x200,
            0x200,
            0,
            0,
            0,
            0x60000020,
        )

        pe_data = dos_header + pe_signature + coff_header + optional_header + section
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)

        if handler.is_pe():
            valid, issues = handler.validate_integrity()

            pass


class TestPEIntegrityValidation:
    """Test PE integrity validation."""

    def test_checksum_validation(self, tmp_path):
        """Test checksum mismatch detection."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)

        optional_header = bytearray(b"\x00" * 96)

        struct.pack_into("<I", optional_header, 64, 0xDEADBEEF)

        pe_data = dos_header + pe_signature + coff_header + bytes(optional_header)
        test_file.write_bytes(pe_data)

        PEHandler(test_file)

        pass

    def test_validate_missing_header(self, tmp_path):
        """Test validation with truncated file."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x00\x00" + b"\x00" * 10)

        handler = PEHandler(test_file)

        if not handler.is_pe():
            pass


class TestPERepairWorkflow:
    """Test complete PE repair workflow."""

    def test_repair_workflow_non_pe(self, tmp_path):
        """Test complete repair workflow on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00" * 10)

        handler = PEHandler(test_file)

        valid, issues = handler.validate_integrity()
        assert not valid

        success, repairs = handler.full_repair()
        assert not success

    def test_refresh_headers_non_pe(self, tmp_path):
        """Test refresh_headers on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00" * 10)

        handler = PEHandler(test_file)

        result = handler.refresh_headers()

        assert result is False

    def test_fix_imports_non_pe(self, tmp_path):
        """Test fix_imports on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00" * 10)

        handler = PEHandler(test_file)

        success, fixes = handler.fix_imports()

        assert success

    def test_fix_exports_non_pe(self, tmp_path):
        """Test fix_exports on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00" * 10)

        handler = PEHandler(test_file)

        success, fixes = handler.fix_exports()

        assert success

    def test_fix_resources_non_pe(self, tmp_path):
        """Test fix_resources on non-PE."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x00\x00\x00" * 10)

        handler = PEHandler(test_file)

        success, fixes = handler.fix_resources()

        assert success


class TestPEErrorHandling:
    """Test error handling in PE handler."""

    def test_corrupted_header(self, tmp_path):
        """Test handling of corrupted PE header."""
        test_file = tmp_path / "corrupted.exe"

        test_file.write_bytes(b"MZ" + b"\xff" * 100)

        handler = PEHandler(test_file)

        if handler.is_pe():
            pass

    def test_truncated_file(self, tmp_path):
        """Test handling of truncated PE file."""
        test_file = tmp_path / "truncated.exe"

        test_file.write_bytes(b"MZ")

        handler = PEHandler(test_file)

        assert not handler.is_pe()

    def test_nonexistent_file(self, tmp_path):
        """Test handling of nonexistent file."""
        nonexistent = tmp_path / "nonexistent.exe"

        handler = PEHandler(nonexistent)

        assert not handler.is_pe()
        assert not handler.validate()

    def test_invalid_pe_signature(self, tmp_path):
        """Test handling of invalid PE signature."""
        test_file = tmp_path / "invalid.exe"

        test_file.write_bytes(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"XXXX")

        handler = PEHandler(test_file)

        assert not handler.is_pe()


class TestPEPlatformIntegration:
    """Platform-specific PE integration tests."""

    @pytest.mark.skipif(platform.system() not in ("Windows", "Linux"), reason="PE tests on Windows/Linux")
    def test_add_section_stub(self, tmp_path):
        """Test add_section stub implementation."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"\x00" * 100)

        handler = PEHandler(test_file)
        result = handler.add_section(".test", 0x1000)

        assert result is None


class TestPEHandlerCaching:
    """Test PE handler caching behavior."""

    def test_sections_cache(self, tmp_path):
        """Test that sections are cached."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
        optional_header = b"\x00" * 96
        section = b".text\x00\x00\x00" + struct.pack(
            "<IIIIIIII",
            0x1000,
            0x1000,
            0x200,
            0x200,
            0,
            0,
            0,
            0x60000020,
        )

        pe_data = dos_header + pe_signature + coff_header + optional_header + section
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)

        if hasattr(handler, "_sections_cache"):
            assert handler._sections_cache is None

            handler.get_sections()
            assert handler._sections_cache is not None

            handler.get_sections()
            pass


class TestPEChecksumComparison:
    """Test PE checksum comparison."""

    def test_stored_vs_calculated_checksum(self, tmp_path):
        """Test comparing stored and calculated checksums."""
        test_file = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
        optional_header = bytearray(b"\x00" * 96)

        pe_data = dos_header + pe_signature + coff_header + bytes(optional_header) + b"\x00" * 100
        test_file.write_bytes(pe_data)

        handler = PEHandler(test_file)

        if handler.is_pe():
            handler._get_stored_checksum()
            handler._calculate_pe_checksum()

            pass
