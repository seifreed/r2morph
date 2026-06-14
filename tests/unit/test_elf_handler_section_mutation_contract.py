import sys
from pathlib import Path
from types import SimpleNamespace

from r2morph.platform.elf_handler_section_mutation import add_section


class _FakeSection:
    class TYPE:
        PROGBITS = "PROGBITS"

    class FLAGS:
        def __new__(cls, value):
            return value

    def __init__(self, name: str) -> None:
        self.name = name
        self.type = None
        self.flags = None
        self.content = None
        self.alignment = None


class _FakeBinary:
    def __init__(self) -> None:
        self.sections = {}
        self.written = False

    def get_section(self, name: str):
        return self.sections.get(name)

    def add(self, section, loaded: bool = True):
        added = SimpleNamespace(virtual_address=0x401000)
        self.sections[section.name] = added
        return added

    def write(self, path: str) -> None:
        self.written = True


def test_elf_handler_section_mutation_contract(monkeypatch, tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.elf"
    binary_path.write_bytes(b"\x7fELF" + b"\x00" * 64)

    fake_binary = _FakeBinary()
    fake_lief = SimpleNamespace(
        parse=lambda _: fake_binary,
        ELF=SimpleNamespace(Binary=_FakeBinary, Section=_FakeSection),
    )
    monkeypatch.setitem(sys.modules, "lief", fake_lief)

    assert add_section(binary_path, ".morph", 16) == 0x401000
    assert fake_binary.written is True
