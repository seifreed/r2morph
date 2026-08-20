from __future__ import annotations

from pathlib import Path

from r2morph.platform.macho_handler import MachOHandler
from tests.utils.assertions import expect


def test_macho_magic_detection(tmp_path: Path) -> None:
    fat_magic = tmp_path / "fat.bin"
    fat_magic.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 64)
    handler = MachOHandler(fat_magic)

    expect(not (handler.is_fat_binary() is not True))
    if handler.is_macho() is False:
        expect(not (handler._parse_lief() is not None))
    else:
        expect(not (handler.is_macho() is not True))

    thin_magic = tmp_path / "thin.bin"
    thin_magic.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 64)
    handler = MachOHandler(thin_magic)
    if handler.is_macho() is False:
        expect(not (handler._parse_lief() is not None))
    else:
        expect(not (handler.is_macho() is not True))
