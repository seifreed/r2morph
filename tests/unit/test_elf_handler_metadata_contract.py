from r2morph.platform.elf_handler_metadata import get_architecture, get_entry_point


def test_elf_handler_metadata_contract() -> None:
    header = {
        "e_entry": 0x401000,
        "e_machine": 0x3E,
        "is_64bit": True,
        "is_little_endian": True,
    }

    assert get_entry_point(header) == 0x401000
    assert get_architecture(header) == {
        "machine": 0x3E,
        "machine_name": "x86_64",
        "bits": 64,
        "endian": "little",
    }
