"""Characterization of MachOHandler._parse_macho_basic on a real arm64 binary.

_parse_macho_basic is the LIEF-free fallback parser. It is exercised here
directly against dataset/macho_arm64 (a real thin arm64 Mach-O) so the magic
detection and load-command parsing can be refactored without changing
observable output. No mocks (CLAUDE.md sec.4): the real handler parses a real
on-disk binary.
"""

from pathlib import Path

from r2morph.platform.macho_handler import MachOHandler


def test_parse_macho_basic_real_arm64() -> None:
    handler = MachOHandler(Path("dataset/macho_arm64"))

    commands, segments = handler._parse_macho_basic()

    command_names = [command["command"] for command in commands]
    assert len(command_names) == 17
    assert command_names[:4] == ["LC_SEGMENT_64"] * 4
    assert "LC_SYMTAB" in command_names
    assert "LC_DYSYMTAB" in command_names
    assert "LC_UUID" in command_names
    assert "LC_BUILD_VERSION" in command_names

    assert [segment["name"] for segment in segments] == [
        "__PAGEZERO",
        "__TEXT",
        "__DATA_CONST",
        "__LINKEDIT",
    ]

    text = next(segment for segment in segments if segment["name"] == "__TEXT")
    assert text["virtual_address"] == 0x100000000
    assert text["virtual_size"] == 16384
    assert text["file_offset"] == 0
    assert text["file_size"] == 16384

    pagezero = next(segment for segment in segments if segment["name"] == "__PAGEZERO")
    assert pagezero["virtual_address"] == 0
    assert pagezero["virtual_size"] == 4294967296  # 4 GiB __PAGEZERO
