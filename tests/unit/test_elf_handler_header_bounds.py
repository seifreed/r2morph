"""Unit tests for _header_table_within_file, the validate() bounds check."""

from r2morph.platform.elf_handler import _header_table_within_file


def test_table_within_file():
    assert _header_table_within_file(64, 100, 1024, "Section header table") is True


def test_table_exactly_at_end():
    assert _header_table_within_file(64, 960, 1024, "Section header table") is True


def test_table_overflows():
    assert _header_table_within_file(1000, 100, 1024, "Program header table") is False
