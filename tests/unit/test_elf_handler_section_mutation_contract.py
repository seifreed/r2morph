import shutil
from pathlib import Path

import lief

from r2morph.platform.elf_handler_section_mutation import add_section
from tests.utils.assertions import expect

_ELF_FIXTURE = Path(__file__).parents[2] / "fixtures" / "dataset" / "elf_vm_arith_x86_64"


def test_elf_handler_section_mutation_persists_new_section(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.elf"
    shutil.copy2(_ELF_FIXTURE, binary_path)

    address = add_section(binary_path, ".morph", 16)
    binary = lief.ELF.parse(binary_path)

    expect(address is not None and binary is not None and binary.get_section(".morph") is not None)
