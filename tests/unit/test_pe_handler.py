"""
Unit tests for PE handler module.
"""

import struct
from pathlib import Path

from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect

_EXPECTED_CHECKSUM_3735928559 = 0xDEADBEEF


class TestPEHandlerInit:
    def test_init_with_path(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        expect(handler.binary_path == binary_path)

    def test_init_resets_caches(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        expect(not (handler._binary is not None))
        expect(not (handler._pe_offset is not None))
        expect(not (handler._sections_cache is not None))


class TestIsPe:
    def test_is_pe_valid_mz_header(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        pe_sig = b"PE\x00\x00"
        mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
        binary_path.write_bytes(mz_header + pe_sig + b"\x00" * 100)
        handler = PEHandler(binary_path)
        expect(not (handler.is_pe() is not True))

    def test_is_pe_invalid_mz(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"ELF" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        expect(not (handler.is_pe() is not False))

    def test_is_pe_missing_pe_sig(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        expect(not (handler.is_pe() is not False))

    def test_is_pe_short_file(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ")
        handler = PEHandler(binary_path)
        expect(not (handler.is_pe() is not False))

    def test_is_pe_nonexistent_file(self, tmp_path):
        handler = PEHandler(tmp_path / "nonexistent.exe")
        expect(not (handler.is_pe() is not False))


class TestGetChecksumOffset:
    def test_get_checksum_offset_valid_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        pe_sig = b"PE\x00\x00"
        mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
        binary_path.write_bytes(mz_header + pe_sig + b"\x00" * 100)
        handler = PEHandler(binary_path)
        offset = handler.get_checksum_offset()
        expect(offset is not None)
        expect(offset == 64 + 24 + 64)

    def test_get_checksum_offset_invalid_file(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"invalid")
        handler = PEHandler(binary_path)
        expect(not (handler.get_checksum_offset() is not None))


class TestCalculateChecksum:
    def test_calculate_checksum_simple(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        checksum = handler._calculate_checksum()
        expect(isinstance(checksum, int))
        expect(not (checksum < 0))


class TestFixChecksum:
    def test_fix_checksum_not_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"not a pe")
        handler = PEHandler(binary_path)
        result = handler.fix_checksum()
        expect(not (result is not False))


class TestGetSections:
    def test_get_sections_not_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"not a pe")
        handler = PEHandler(binary_path)
        sections = handler.get_sections()
        expect(sections == [])

    def test_get_sections_uses_cache(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        pe_sig = b"PE\x00\x00"
        mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
        coff_machine = struct.pack("<H", 0x14C)
        coff_num_sections = struct.pack("<H", 0)
        coff_timestamp = struct.pack("<I", 0)
        coff_ptr_symbols = struct.pack("<I", 0)
        coff_num_symbols = struct.pack("<I", 0)
        coff_size_optional = struct.pack("<H", 96)
        coff_characteristics = struct.pack("<H", 0x102)
        coff_header = (
            coff_machine
            + coff_num_sections
            + coff_timestamp
            + coff_ptr_symbols
            + coff_num_symbols
            + coff_size_optional
            + coff_characteristics
        )
        binary_path.write_bytes(mz_header + pe_sig + coff_header + b"\x00" * 500)
        handler = PEHandler(binary_path)
        sections1 = handler.get_sections()
        sections2 = handler.get_sections()
        expect(sections1 == sections2)


class TestGetImports:
    def test_get_imports_no_lief(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        imports = handler.get_imports()
        expect(imports == [])


class TestGetExports:
    def test_get_exports_no_lief(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        exports = handler.get_exports()
        expect(exports == [])


class TestGetRelocations:
    def test_get_relocations_no_lief(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        relocations = handler.get_relocations()
        expect(relocations == [])


class TestValidateIntegrity:
    def test_validate_integrity_not_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"not a pe")
        handler = PEHandler(binary_path)
        is_valid, issues = handler.validate_integrity()
        expect(not (is_valid is not False))
        expect(not ("Not a PE binary" not in issues))

    def test_validate_integrity_valid_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        pe_sig = b"PE\x00\x00"
        mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
        coff_machine = struct.pack("<H", 0x14C)
        coff_num_sections = struct.pack("<H", 0)
        coff_timestamp = struct.pack("<I", 0)
        coff_ptr_symbols = struct.pack("<I", 0)
        coff_num_symbols = struct.pack("<I", 0)
        coff_size_optional = struct.pack("<H", 96)
        coff_characteristics = struct.pack("<H", 0x102)
        coff_header = (
            coff_machine
            + coff_num_sections
            + coff_timestamp
            + coff_ptr_symbols
            + coff_num_symbols
            + coff_size_optional
            + coff_characteristics
        )
        binary_path.write_bytes(mz_header + pe_sig + coff_header + b"\x00" * 500)
        handler = PEHandler(binary_path)
        is_valid, issues = handler.validate_integrity()
        expect(isinstance(is_valid, bool))
        expect(isinstance(issues, list))


class TestRepairIntegrity:
    def test_repair_integrity_not_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"not a pe")
        handler = PEHandler(binary_path)
        success, repairs = handler.repair_integrity()
        expect(not (success is not False))
        expect(not ("Not a PE binary" not in repairs))


class TestValidate:
    def test_validate_not_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"not a pe")
        handler = PEHandler(binary_path)
        expect(not (handler.validate() is not False))

    def test_validate_valid_pe(self):
        binary_path = Path(__file__).parents[2] / "fixtures" / "dataset" / "pe_x86_64.exe"
        handler = PEHandler(binary_path)
        result = handler.validate()
        expect(not (result is not True))


class TestAddSection:
    def test_add_section_returns_none(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        result = handler.add_section(".test", 1024)
        expect(not (result is not None))


class TestRefreshHeaders:
    def test_refresh_headers_not_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"not a pe")
        handler = PEHandler(binary_path)
        result = handler.refresh_headers()
        expect(not (result is not False))


class TestFixImports:
    def test_fix_imports_no_lief(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        success, fixes = handler.fix_imports()
        expect(not (success is not True))
        expect(fixes == [])


class TestFixExports:
    def test_fix_exports_no_lief(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        success, fixes = handler.fix_exports()
        expect(not (success is not True))
        expect(fixes == [])


class TestFixResources:
    def test_fix_resources_no_lief(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        success, fixes = handler.fix_resources()
        expect(not (success is not True))
        expect(fixes == [])


class TestFullRepair:
    def test_full_repair_not_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"not a pe")
        handler = PEHandler(binary_path)
        is_valid, issues = handler.validate_integrity()
        expect(not (is_valid is not False))
        expect(not ("Not a PE binary" not in issues))


class TestReadPEHeader:
    def test_read_pe_header_invalid_mz(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"ELF" + b"\x00" * 100)
        handler = PEHandler(binary_path)
        header = handler._read_pe_header()
        expect(not (header is not None))

    def test_read_pe_header_short_file(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ")
        handler = PEHandler(binary_path)
        header = handler._read_pe_header()
        expect(not (header is not None))


class TestPE32Header:
    def test_pe32_plus_detection_valid(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
        pe_sig = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x14C, 0, 0, 0, 0, 240, 0x102)
        opt_magic = struct.pack("<H", 0x20B)
        optional_header = opt_magic + b"\x00" * 238
        binary_data = mz_header + pe_sig + coff_header + optional_header + b"\x00" * 500
        binary_path.write_bytes(binary_data)
        handler = PEHandler(binary_path)
        expect(not (handler.is_pe() is not True))


class TestSectionsParsing:
    def test_parse_sections_not_pe(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"not a pe file at all")
        handler = PEHandler(binary_path)
        sections = handler.get_sections()
        expect(sections == [])

    def test_parse_sections_short_file(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 10)
        handler = PEHandler(binary_path)
        sections = handler.get_sections()
        expect(sections == [])

    def test_parse_sections_uses_cache(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
        pe_sig = b"PE\x00\x00"
        coff_header = b"\x00" * 20
        binary_path.write_bytes(mz_header + pe_sig + coff_header + b"\x00" * 500)
        handler = PEHandler(binary_path)
        sections1 = handler.get_sections()
        sections2 = handler.get_sections()
        expect(sections1 == sections2)


class TestGetStoredChecksum:
    def test_get_stored_checksum_valid(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        pe_offset = 0x40
        mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
        pe_sig = b"PE\x00\x00"
        coff_header = b"\x00" * 20
        opt_magic = struct.pack("<H", 0x10B)
        opt_data = b"\x00" * 62
        test_checksum = struct.pack("<I", 0xDEADBEEF)
        optional_header = opt_magic + opt_data + test_checksum + b"\x00" * 26
        binary_path.write_bytes(mz_header + pe_sig + coff_header + optional_header + b"\x00" * 500)
        handler = PEHandler(binary_path)
        checksum = handler._get_stored_checksum()
        expect(checksum == _EXPECTED_CHECKSUM_3735928559)

    def test_get_stored_checksum_invalid(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"invalid")
        handler = PEHandler(binary_path)
        checksum = handler._get_stored_checksum()
        expect(checksum == 0)


class TestCalculatePeChecksum:
    def test_calculate_pe_checksum_basic(self, tmp_path):
        binary_path = tmp_path / "test.exe"
        pe_offset = 0x40
        mz_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", pe_offset)
        pe_sig = b"PE\x00\x00"
        coff_header = b"\x00" * 20
        optional_header = b"\x00" * 96
        binary_path.write_bytes(mz_header + pe_sig + coff_header + optional_header + b"\x00" * 100)
        handler = PEHandler(binary_path)
        checksum = handler._calculate_pe_checksum()
        expect(isinstance(checksum, int))
        expect(not (checksum < 0))
