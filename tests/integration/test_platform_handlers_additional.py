from pathlib import Path

import pytest

from r2morph.platform.elf_handler import ELFHandler
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect


def test_elf_handler_header_and_validation():
    elf_path = Path("fixtures/dataset/elf_x86_64")
    if not elf_path.exists():
        pytest.skip("ELF binary not available")

    handler = ELFHandler(elf_path)
    expect(not (handler.is_elf() is not True))
    expect(not (handler.validate() is not True))

    header = handler._parse_elf_header()
    expect(header is not None)
    expect(not (handler._is_64bit not in {True, False}))
    expect(not (handler._is_little_endian not in {True, False}))

    # Ensure cached header is reused
    cached = handler._parse_elf_header()
    expect(not (cached is not header))


def test_pe_handler_checksum_and_validation(tmp_path: Path):
    pe_path = Path("fixtures/dataset/pe_x86_64.exe")
    if not pe_path.exists():
        pytest.skip("PE binary not available")

    pe_copy = tmp_path / "pe_x86_64_copy.exe"
    pe_copy.write_bytes(pe_path.read_bytes())

    handler = PEHandler(pe_copy)
    expect(not (handler.is_pe() is not True))
    expect(not (handler.validate() is not True))

    checksum_before = handler._calculate_checksum()
    expect(isinstance(checksum_before, int))

    expect(not (handler.fix_checksum() is not True))
    checksum_after = handler._calculate_checksum()
    expect(isinstance(checksum_after, int))
