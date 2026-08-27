"""Property coverage for malformed ELF parser input."""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from r2morph.platform.elf_handler_parsing import parse_elf_header
from tests.utils.assertions import expect


@settings(max_examples=40, deadline=1000)
@given(payload=st.binary(max_size=256))
def test_elf_parser_handles_arbitrary_bytes_with_bounded_result(payload: bytes) -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "candidate"
        path.write_bytes(payload)
        header, is_64bit, is_little_endian = parse_elf_header(path)

    expect(
        (
            header is None or isinstance(header, dict),
            is_64bit is None or isinstance(is_64bit, bool),
            is_little_endian is None or isinstance(is_little_endian, bool),
        )
        == (True, True, True)
    )
