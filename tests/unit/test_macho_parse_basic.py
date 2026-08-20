"""Characterization of MachOHandler._parse_macho_basic on a real arm64 binary.

_parse_macho_basic is the LIEF-free fallback parser. It is exercised here
directly against fixtures/dataset/macho_arm64 (a real thin arm64 Mach-O) so the magic
detection and load-command parsing can be refactored without changing
observable output. No mocks (CLAUDE.md sec.4): the real handler parses a real
on-disk binary.
"""

from pathlib import Path

from r2morph.platform.macho_handler import MachOHandler
from tests.utils.assertions import expect

_EXPECTED_LEN_COMMAND_NAMES_17 = 17
_EXPECTED_PAGEZERO_VIRTUAL_SIZE_4294967296 = 4294967296
_EXPECTED_TEXT_FILE_SIZE_16384 = 16384
_EXPECTED_TEXT_VIRTUAL_ADDRESS_4294967296 = 0x100000000
_EXPECTED_TEXT_VIRTUAL_SIZE_16384 = 16384


def test_parse_macho_basic_real_arm64() -> None:
    handler = MachOHandler(Path("fixtures/dataset/macho_arm64"))

    commands, segments = handler._parse_macho_basic()

    command_names = [command["command"] for command in commands]
    expect(len(command_names) == _EXPECTED_LEN_COMMAND_NAMES_17)
    expect(command_names[:4] == ["LC_SEGMENT_64"] * 4)
    expect(not ("LC_SYMTAB" not in command_names))
    expect(not ("LC_DYSYMTAB" not in command_names))
    expect(not ("LC_UUID" not in command_names))
    expect(not ("LC_BUILD_VERSION" not in command_names))

    expect([segment["name"] for segment in segments] == ["__PAGEZERO", "__TEXT", "__DATA_CONST", "__LINKEDIT"])

    text = next(segment for segment in segments if segment["name"] == "__TEXT")
    expect(text["virtual_address"] == _EXPECTED_TEXT_VIRTUAL_ADDRESS_4294967296)
    expect(text["virtual_size"] == _EXPECTED_TEXT_VIRTUAL_SIZE_16384)
    expect(text["file_offset"] == 0)
    expect(text["file_size"] == _EXPECTED_TEXT_FILE_SIZE_16384)

    pagezero = next(segment for segment in segments if segment["name"] == "__PAGEZERO")
    expect(pagezero["virtual_address"] == 0)
    expect(pagezero["virtual_size"] == _EXPECTED_PAGEZERO_VIRTUAL_SIZE_4294967296)
