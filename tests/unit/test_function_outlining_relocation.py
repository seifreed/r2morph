from __future__ import annotations

from typing import Any

from r2morph.mutations.function_outlining import FunctionOutliningPass, OutlinedChunk
from tests.utils.assertions import expect

_CHUNK_ADDRESS = 0x1000
_LINEAR_PREFIX_SIZE = 5


class _ChunkBinary:
    def read_bytes(self, address: int, size: int) -> bytes:
        if address == _CHUNK_ADDRESS and size == _LINEAR_PREFIX_SIZE:
            return b"\x89\xd8\x83\xc0\x01"
        return b""


def _chunk_with_branch_terminator() -> OutlinedChunk:
    instructions: list[dict[str, Any]] = [
        {"offset": _CHUNK_ADDRESS, "size": 2, "disasm": "mov eax, ebx"},
        {"offset": 0x1002, "size": 3, "disasm": "add eax, 1"},
        {"offset": 0x1005, "size": 2, "type": "cjmp", "disasm": "je 0x1010", "jump": 0x1010},
    ]
    return OutlinedChunk(1, _CHUNK_ADDRESS, instructions)


def test_chunk_bytes_relocates_linear_prefix_before_branch() -> None:
    data = FunctionOutliningPass._chunk_bytes(_ChunkBinary(), _chunk_with_branch_terminator())

    expect(data is not None and data[0] == _CHUNK_ADDRESS)


def test_chunk_bytes_excludes_branch_from_relocated_size() -> None:
    data = FunctionOutliningPass._chunk_bytes(_ChunkBinary(), _chunk_with_branch_terminator())

    expect(data is not None and data[1] == _LINEAR_PREFIX_SIZE)


def test_chunk_bytes_rejects_noncontiguous_instruction_stream() -> None:
    chunk = OutlinedChunk(
        1,
        _CHUNK_ADDRESS,
        [
            {"offset": _CHUNK_ADDRESS, "size": 2, "disasm": "mov eax, ebx"},
            {"offset": 0x1003, "size": 3, "disasm": "add eax, 1"},
        ],
    )

    expect(FunctionOutliningPass._chunk_bytes(_ChunkBinary(), chunk) is None)


def test_chunk_bytes_rejects_pc_relative_memory_instruction() -> None:
    chunk = OutlinedChunk(
        1,
        _CHUNK_ADDRESS,
        [
            {
                "offset": _CHUNK_ADDRESS,
                "size": 7,
                "bytes": "488d0534120000",
                "disasm": "lea rax, [0x223b]",
            }
        ],
    )

    expect(FunctionOutliningPass._chunk_bytes(_ChunkBinary(), chunk) is None)
