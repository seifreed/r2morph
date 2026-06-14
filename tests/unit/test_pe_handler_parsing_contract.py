import struct
from pathlib import Path

from r2morph.platform.pe_handler_parsing import (
    calculate_pe_checksum,
    get_checksum_offset,
    get_sections_fallback,
    parse_coff_header,
    parse_optional_header,
    parse_pe_section_entry,
    read_pe_header,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PE_BINARY = _REPO_ROOT / "dataset" / "pe_x86_64.exe"


def test_pe_handler_parsing_round_trip() -> None:
    coff_header = (
        b"\x4c\x01"
        + b"\x03\x00"
        + b"\x01\x02\x03\x04"
        + b"\x05\x06\x07\x08"
        + b"\x09\x0a\x0b\x0c"
        + b"\xe0\x00"
        + b"\x02\x01"
    )
    optional_header = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        14,
        0,
        0x1000,
        0x2000,
        0,
        0x1000,
        0,
        0x140000000,
        0x1000,
        0x200,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x4000,
        0x200,
        0,
        3,
        0x8540,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    section = (
        b".text\x00\x00\x00"
        + b"\x00\x10\x00\x00"
        + b"\x00\x20\x00\x00"
        + b"\x00\x08\x00\x00"
        + b"\x00\x04\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x20\x00\x00\x60"
    )

    coff = parse_coff_header(coff_header)
    opt = parse_optional_header(optional_header, True)
    sec = parse_pe_section_entry(section)
    header = read_pe_header(_PE_BINARY)

    assert coff["num_sections"] == 3
    assert opt["entry_point"] == 0x1000
    assert sec["name"] == ".text"
    assert sec["size"] == 0x1000
    assert header is not None
    assert header["checksum_offset"] == header["optional_header_offset"] + 64
    assert get_checksum_offset(_PE_BINARY) == header["checksum_offset"]
    assert calculate_pe_checksum(_PE_BINARY) >= 0
    assert len(get_sections_fallback(_PE_BINARY)) >= 1
