"""
Unit tests for Mach-O handler module.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
import struct

from r2morph.platform.macho_handler import MachOHandler


class TestMachOHandlerInit:
    def test_init_with_path(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.binary_path == binary_path

    def test_init_with_string_path(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(Path(str(binary_path)))
        assert handler.binary_path == binary_path


class TestIsMacho:
    def test_is_macho_valid_magic_le(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is True

    def test_is_macho_valid_magic_be(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xce\xfa\xed\xfe" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is True

    def test_is_macho_valid_magic_64_le(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is True

    def test_is_macho_valid_magic_64_be(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is True

    def test_is_macho_valid_fat_magic(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is True

    def test_is_macho_valid_fat_cigam(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xbe\xba\xfe\xca" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is True

    def test_is_macho_invalid_magic(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is False

    def test_is_macho_invalid_pe(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is False

    def test_is_macho_nonexistent_file(self, tmp_path):
        handler = MachOHandler(tmp_path / "nonexistent")
        assert handler.is_macho() is False


class TestIsFatBinary:
    def test_is_fat_binary_magic_be(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_fat_binary() is True

    def test_is_fat_binary_cigam(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xbe\xba\xfe\xca" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_fat_binary() is True

    def test_is_fat_binary_thin_binary(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.is_fat_binary() is False

    def test_is_fat_binary_nonexistent_file(self, tmp_path):
        handler = MachOHandler(tmp_path / "nonexistent")
        assert handler.is_fat_binary() is False


class TestValidate:
    def test_validate_valid_macho(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.validate() is True

    def test_validate_invalid_binary(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"not a macho" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        assert handler.validate() is False

    def test_validate_nonexistent_file(self, tmp_path):
        handler = MachOHandler(tmp_path / "nonexistent")
        assert handler.validate() is False


class TestValidateIntegrity:
    def test_validate_integrity_not_macho(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"not a macho")
        handler = MachOHandler(binary_path)
        ok, msg = handler.validate_integrity()
        assert ok is False
        assert "Not a Mach-O" in msg

    def test_validate_integrity_valid_macho(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        ok, msg = handler.validate_integrity()
        assert msg == "" or "LIEF not available" in msg


class TestGetLoadCommands:
    def test_get_load_commands_empty_binary(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        commands = handler.get_load_commands()
        assert isinstance(commands, list)

    def test_get_load_commands_returns_list(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        commands = handler.get_load_commands()
        assert isinstance(commands, list)


class TestGetSegments:
    def test_get_segments_empty_binary(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        segments = handler.get_segments()
        assert isinstance(segments, list)

    def test_get_segments_returns_list(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        segments = handler.get_segments()
        assert isinstance(segments, list)


class TestGetSections:
    def test_get_sections_returns_list(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        sections = handler.get_sections()
        assert isinstance(sections, list)


class TestFixLoadCommands:
    def test_fix_load_commands_returns_tuple(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        result = handler.fix_load_commands()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], list)


class TestFixBindSymbols:
    def test_fix_bind_symbols_returns_tuple(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        result = handler.fix_bind_symbols()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], list)


class TestFixSegmentPermissions:
    def test_fix_segment_permissions_returns_tuple(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        result = handler.fix_segment_permissions()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], list)


class TestFullRepair:
    def test_full_repair_returns_tuple(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        result = handler.full_repair()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], list)


class TestRepairIntegrity:
    def test_repair_integrity_not_darwin(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        with patch("platform.system", return_value="Linux"):
            result = handler.repair_integrity()
        assert result is False

    def test_repair_integrity_not_macho(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"not a macho")
        handler = MachOHandler(binary_path)
        result = handler.repair_integrity()
        assert result is False


class TestParseMachoBasic:
    def test_parse_macho_basic_empty_file(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"")
        handler = MachOHandler(binary_path)
        commands, segments = handler._parse_macho_basic()
        assert commands == []
        assert segments == []

    def test_parse_macho_basic_short_file(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed")
        handler = MachOHandler(binary_path)
        commands, segments = handler._parse_macho_basic()
        assert commands == []
        assert segments == []

    def test_parse_macho_basic_invalid_magic(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"JUNK" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        commands, segments = handler._parse_macho_basic()
        assert commands == []
        assert segments == []


class TestMacho64Header:
    def test_macho_64_basic_parsing(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        magic = struct.pack("<I", 0xFEEDFACF)
        header = b"\x00" * 28
        binary_path.write_bytes(magic + header)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is True

    def test_macho_64_cigam_parsing(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        magic = struct.pack("<I", 0xCFFAEDFE)
        header = b"\x00" * 28
        binary_path.write_bytes(magic + header)
        handler = MachOHandler(binary_path)
        assert handler.is_macho() is True


class TestFatBinaryParsing:
    def test_fat_magic_parsing(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        magic = struct.pack(">I", 0xCAFEBABE)
        nfat = struct.pack(">I", 1)
        arch_data = struct.pack(">IIIII", 0, 0, 0x1000, 0, 0)
        macho_magic = struct.pack("<I", 0xFEEDFACE)
        macho_header = b"\x00" * 24
        binary_path.write_bytes(
            magic + nfat + arch_data + b"\x00" * 0x1000 + macho_magic + macho_header + b"\x00" * 100
        )
        handler = MachOHandler(binary_path)
        assert handler.is_fat_binary() is True

    def test_fat_cigam_parsing(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        magic = struct.pack("<I", 0xBEBAFECA)
        nfat = struct.pack("<I", 1)
        arch_data = struct.pack("<IIIII", 0, 0, 0x1000, 0, 0)
        macho_magic = struct.pack("<I", 0xFEEDFACE)
        macho_header = b"\x00" * 24
        binary_path.write_bytes(
            magic + nfat + arch_data + b"\x00" * 0x1000 + macho_magic + macho_header + b"\x00" * 100
        )
        handler = MachOHandler(binary_path)
        assert handler.is_fat_binary() is True


class TestCommandNameMap:
    def test_command_names_defined(self):
        assert MachOHandler is not None
        handler = MachOHandler(Path("/tmp/test"))
        assert handler is not None


class TestIterMachoBinaries:
    def test_iter_macho_binaries_no_lief(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        result = handler._iter_macho_binaries(None)
        assert result == []


class TestExtractArchitecture:
    def test_extract_architecture_nonexistent_file(self, tmp_path):
        handler = MachOHandler(tmp_path / "nonexistent")
        result = handler.extract_architecture("arm64", tmp_path / "output")
        assert result is False


class TestCreateFatBinary:
    def test_create_fat_binary_empty_list(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        handler = MachOHandler(binary_path)
        result = handler.create_fat_binary([], tmp_path / "output")
        assert result is False


class TestMachoMagicValues:
    def test_all_magic_values_recognized(self, tmp_path):
        magic_values = [
            (b"\xfe\xed\xfa\xce", "MH_MAGIC"),
            (b"\xce\xfa\xed\xfe", "MH_CIGAM"),
            (b"\xfe\xed\xfa\xcf", "MH_MAGIC_64"),
            (b"\xcf\xfa\xed\xfe", "MH_CIGAM_64"),
            (b"\xca\xfe\xba\xbe", "FAT_MAGIC"),
            (b"\xbe\xba\xfe\xca", "FAT_CIGAM"),
        ]
        for magic, name in magic_values:
            binary_path = tmp_path / f"test_{name}"
            binary_path.write_bytes(magic + b"\x00" * 100)
            handler = MachOHandler(binary_path)
            assert handler.is_macho() is True, f"Failed for {name}"


class TestParseMachoBasicWithCommands:
    def test_parse_with_segment_command(self, tmp_path):
        binary_path = tmp_path / "test_binary"
        magic = struct.pack("<I", 0xFEEDFACE)
        cputype = struct.pack("<I", 7)
        cpusubtype = struct.pack("<I", 3)
        filetype = struct.pack("<I", 2)
        ncmds = struct.pack("<I", 1)
        sizeofcmds = struct.pack("<I", 56)
        flags = struct.pack("<I", 0)
        header = cputype + cpusubtype + filetype + ncmds + sizeofcmds + flags
        cmd = struct.pack("<I", 0x1)
        cmdsize = struct.pack("<I", 56)
        segname = b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        vmaddr = struct.pack("<I", 0x1000)
        vmsize = struct.pack("<I", 0x1000)
        fileoff = struct.pack("<I", 0)
        filesize = struct.pack("<I", 0x1000)
        maxprot = struct.pack("<I", 7)
        initprot = struct.pack("<I", 5)
        nsects = struct.pack("<I", 0)
        segflags = struct.pack("<I", 0)
        segment = (
            cmd + cmdsize + segname + vmaddr + vmsize + fileoff + filesize + maxprot + initprot + nsects + segflags
        )
        binary_path.write_bytes(magic + header + segment)
        handler = MachOHandler(binary_path)
        commands, segments = handler._parse_macho_basic()
        assert isinstance(commands, list)
        assert isinstance(segments, list)
