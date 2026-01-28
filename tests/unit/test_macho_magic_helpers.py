from __future__ import annotations

from pathlib import Path

from r2morph.platform.macho_handler import MachOHandler


def test_macho_magic_detection(tmp_path: Path) -> None:
    fat_magic = tmp_path / "fat.bin"
    fat_magic.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 64)
    handler = MachOHandler(fat_magic)

    assert handler.is_fat_binary() is True
    if handler.is_macho() is False:
        assert handler._parse_lief() is None
    else:
        assert handler.is_macho() is True

    thin_magic = tmp_path / "thin.bin"
    thin_magic.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 64)
    handler = MachOHandler(thin_magic)
    if handler.is_macho() is False:
        assert handler._parse_lief() is None
    else:
        assert handler.is_macho() is True
