"""Contract tests for binary integrity repair helpers."""

from __future__ import annotations

from r2morph.validation.integrity_repair_helpers import (
    repair_elf_integrity,
    repair_macho_integrity,
    repair_pe_integrity,
)


class _ElfHandler:
    def fix_section_headers(self) -> bool:
        return True

    def fix_program_headers(self) -> bool:
        return True


class _MachoHandler:
    def repair_integrity(self) -> bool:
        return True

    def mark_executable(self) -> None:
        return None


class _PeHandler:
    def repair_integrity(self) -> tuple[bool, list[str]]:
        return True, ["Repaired PE checksum"]

    def refresh_headers(self) -> None:
        return None


def test_integrity_repair_helpers_contract() -> None:
    assert repair_elf_integrity(_ElfHandler()) == (True, ["Fixed section headers", "Fixed program headers"])
    assert repair_macho_integrity(_MachoHandler()) == (True, ["Repaired Mach-O signature", "Marked executable"])
    assert repair_pe_integrity(_PeHandler()) == (True, ["Repaired PE checksum", "Refreshed PE headers"])
