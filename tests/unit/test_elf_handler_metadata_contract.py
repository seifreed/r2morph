from r2morph.platform.elf_handler_metadata import get_architecture, get_entry_point
from tests.utils.assertions import expect

_EXPECTED_GET_ENTRY_POINT_HEADER_4198400 = 0x401000


def test_elf_handler_metadata_contract() -> None:
    header = {
        "e_entry": 0x401000,
        "e_machine": 0x3E,
        "is_64bit": True,
        "is_little_endian": True,
    }

    expect(get_entry_point(header) == _EXPECTED_GET_ENTRY_POINT_HEADER_4198400)
    expect(get_architecture(header) == {"machine": 62, "machine_name": "x86_64", "bits": 64, "endian": "little"})
