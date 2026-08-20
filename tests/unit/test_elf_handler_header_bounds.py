"""Unit tests for _header_table_within_file, the validate() bounds check."""

from r2morph.platform.elf_structs import _header_table_within_file
from tests.utils.assertions import expect


def test_table_within_file():
    expect(not (_header_table_within_file(64, 100, 1024, "Section header table") is not True))


def test_table_exactly_at_end():
    expect(not (_header_table_within_file(64, 960, 1024, "Section header table") is not True))


def test_table_overflows():
    expect(not (_header_table_within_file(1000, 100, 1024, "Program header table") is not False))
