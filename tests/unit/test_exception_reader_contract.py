import struct

from r2morph.analysis.exception_reader import ExceptionInfoReader
from tests._doubles.in_memory_pe_pdata_binary import InMemoryPEPdataBinary


def _packed_entry(begin: int, function_length_units: int) -> bytes:
    second = 0x1 | ((function_length_units & 0x7FF) << 2)
    return struct.pack("<II", begin, second)


def test_exception_reader_parses_pe_pdata_entries() -> None:
    pdata = _packed_entry(0x1000, 0x10) + _packed_entry(0x2000, 0x08)
    binary = InMemoryPEPdataBinary(
        bits=32,
        pdata_addr=0x4000,
        pdata_declared_size=len(pdata),
        pdata_bytes=pdata,
    )

    frames = ExceptionInfoReader(binary).read_exception_frames()

    assert set(frames) == {0x1000, 0x2000}
    assert frames[0x1000].function_end == 0x1000 + 0x10 * 2
    assert frames[0x2000].function_end == 0x2000 + 0x08 * 2
