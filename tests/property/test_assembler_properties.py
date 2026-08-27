"""Property coverage for the real assembler disassembly boundary."""

from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from r2morph.core.binary import Binary
from r2morph.utils.assembler import R2Assembler
from tests.utils.assertions import expect


@given(instruction_bytes=st.binary(max_size=64))
@settings(max_examples=20, deadline=1000)
def test_r2assembler_arbitrary_bytes_return_text_or_none(
    instruction_bytes: bytes,
) -> None:
    with Binary(Path("fixtures/dataset/elf_x86_64")) as binary:
        result = R2Assembler(binary.r2).disassemble(instruction_bytes)

    expect(result is None or isinstance(result, str))
