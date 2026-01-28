from pathlib import Path

import pytest

from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.pe_handler import PEHandler


def test_elf_handler_header_and_validation():
    elf_path = Path("dataset/elf_x86_64")
    if not elf_path.exists():
        pytest.skip("ELF binary not available")

    handler = ELFHandler(elf_path)
    assert handler.is_elf() is True
    assert handler.validate() is True

    header = handler._parse_elf_header()
    assert header is not None
    assert handler._is_64bit in {True, False}
    assert handler._is_little_endian in {True, False}

    # Ensure cached header is reused
    cached = handler._parse_elf_header()
    assert cached is header


def test_pe_handler_checksum_and_validation(tmp_path: Path):
    pe_path = Path("dataset/pe_x86_64.exe")
    if not pe_path.exists():
        pytest.skip("PE binary not available")

    pe_copy = tmp_path / "pe_x86_64_copy.exe"
    pe_copy.write_bytes(pe_path.read_bytes())

    handler = PEHandler(pe_copy)
    assert handler.is_pe() is True
    assert handler.validate() is True

    checksum_before = handler._calculate_checksum()
    assert isinstance(checksum_before, int)

    assert handler.fix_checksum() is True
    checksum_after = handler._calculate_checksum()
    assert isinstance(checksum_after, int)
