"""Unit tests for _find_null_run, the code-cave null-run scanner."""

from r2morph.platform.elf_handler import _find_null_run


def test_no_nulls_returns_none():
    assert _find_null_run(b"\x01\x02\x03", 2) is None


def test_run_shorter_than_min_returns_none():
    assert _find_null_run(b"\x01\x00\x00\x01", 3) is None


def test_run_exactly_min_returns_start():
    assert _find_null_run(b"\x01\x00\x00\x00\x01", 3) == 1


def test_first_qualifying_run_wins():
    assert _find_null_run(b"\x00\x00\x01\x00\x00\x00", 2) == 0


def test_run_resets_on_non_null():
    # two separate 2-byte runs, neither reaches 3
    assert _find_null_run(b"\x00\x00\x01\x00\x00", 3) is None
