from __future__ import annotations

from typing import Any

from r2morph.mutations.function_outlining import FunctionOutliningPass, OutlinedChunk
from r2morph.relocations.cave_finder import CodeCave
from tests.utils.assertions import expect

_CHUNK_ADDRESS = 0x1000
_LINEAR_PREFIX_SIZE = 5
_LINEAR_ADDR_STREAM_SIZE = 9


class _ChunkBinary:
    def read_bytes(self, address: int, size: int) -> bytes:
        if address == _CHUNK_ADDRESS and size == _LINEAR_PREFIX_SIZE:
            return b"\x89\xd8\x83\xc0\x01"
        return b""


class _AddressChunkBinary:
    def read_bytes(self, address: int, size: int) -> bytes:
        if address == _CHUNK_ADDRESS and size == _LINEAR_ADDR_STREAM_SIZE:
            return b"\x89\xd8\x83\xc0\x01\x83\xc0\x02"
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


def test_chunk_bytes_uses_addr_when_radare2_omits_offset() -> None:
    chunk = OutlinedChunk(
        1,
        _CHUNK_ADDRESS,
        [
            {"addr": _CHUNK_ADDRESS, "size": 4, "disasm": "mov eax, ebx"},
            {"addr": 0x1004, "size": 5, "disasm": "add eax, 2"},
        ],
    )

    data = FunctionOutliningPass._chunk_bytes(_AddressChunkBinary(), chunk)

    expect(data is not None and data[1] == _LINEAR_ADDR_STREAM_SIZE)


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


def test_chunk_bytes_rejects_memory_instruction_without_decodable_bytes() -> None:
    chunk = OutlinedChunk(
        1,
        _CHUNK_ADDRESS,
        [
            {
                "offset": _CHUNK_ADDRESS,
                "size": 7,
                "bytes": "not-hex",
                "disasm": "lea rax, [rcx + rdx]",
            }
        ],
    )

    expect(FunctionOutliningPass._chunk_bytes(_ChunkBinary(), chunk) is None)


def test_relocate_chunk_rejects_internal_branch_target() -> None:
    chunk = OutlinedChunk(
        1,
        _CHUNK_ADDRESS,
        [{"offset": _CHUNK_ADDRESS, "size": 5, "disasm": "mov eax, ebx"}],
        branch_targets=(_CHUNK_ADDRESS + 2,),
    )
    caves = [CodeCave(0x2000, 32, ".x", True)]

    relocated, _ = FunctionOutliningPass()._relocate_chunk(_ChunkBinary(), 0, chunk, caves, 0)

    expect(not relocated)
