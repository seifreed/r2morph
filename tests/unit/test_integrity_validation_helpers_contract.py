from __future__ import annotations

from pathlib import Path

from r2morph.validation.integrity_validation_helpers import (
    detect_binary_format,
    validate_elf_integrity,
    validate_macho_integrity,
    validate_pe_integrity,
)


class _ELFHandler:
    def is_elf(self) -> bool:
        return True

    def get_sections(self) -> list[dict[str, object]]:
        return [{"name": ".text"}, {"name": ".data"}]

    def get_segments(self) -> list[dict[str, int]]:
        return [{"virtual_address": 0x1000, "virtual_size": 0x200, "flags": 0x1}]

    def get_entry_point(self) -> int:
        return 0x1010


class _MachOHandler:
    def is_macho(self) -> bool:
        return True

    def validate_integrity(self) -> tuple[bool, str]:
        return True, "ok"

    def get_segments(self) -> list[dict[str, int | str]]:
        return [
            {"name": "__TEXT", "virtual_address": 0x1000, "virtual_size": 0x100},
            {"name": "__LINKEDIT", "virtual_address": 0x2000, "virtual_size": 0x100},
        ]

    def get_load_commands(self) -> list[str]:
        return ["LC_SEGMENT_64"]


class _PEHandler:
    def validate_integrity(self) -> tuple[bool, list[str]]:
        return True, []


def test_detect_binary_format(tmp_path: Path) -> None:
    pe = tmp_path / "pe.bin"
    pe.write_bytes(b"MZ" + b"\x00" * 2)
    elf = tmp_path / "elf.bin"
    elf.write_bytes(b"\x7fELF")
    macho = tmp_path / "macho.bin"
    macho.write_bytes(b"\xfe\xed\xfa\xce")

    assert detect_binary_format(pe) == "pe"
    assert detect_binary_format(elf) == "elf"
    assert detect_binary_format(macho) == "macho"


def test_validate_elf_integrity_and_macho_integrity() -> None:
    assert validate_elf_integrity(_ELFHandler()) == (True, [])
    assert validate_macho_integrity(_MachOHandler()) == (True, [])


def test_validate_pe_integrity_delegates() -> None:
    assert validate_pe_integrity(_PEHandler()) == (True, [])
