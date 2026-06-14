import sys
from pathlib import Path
from types import SimpleNamespace

from r2morph.platform.elf_handler_symbols import collect_symbol_tables


def test_elf_handler_symbols_contract(monkeypatch, tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.elf"
    binary_path.write_bytes(b"\x7fELF" + b"\x00" * 128)

    symbol = SimpleNamespace(
        name="main",
        value=0x401000,
        size=16,
        type="TYPE.FUNC",
        binding="BIND.GLOBAL",
        visibility="VIS.DEFAULT",
        shndx=1,
    )
    elf = SimpleNamespace(
        symtab_symbols=[symbol],
        dynamic_symbols=[symbol],
    )
    monkeypatch.setitem(sys.modules, "lief", SimpleNamespace(parse=lambda _: elf, ELF=SimpleNamespace(Binary=object)))

    tables = collect_symbol_tables(binary_path)

    assert tables == {
        "symtab": [
            {
                "name": "main",
                "value": 0x401000,
                "size": 16,
                "type": "FUNC",
                "binding": "GLOBAL",
                "visibility": "DEFAULT",
                "shndx": 1,
            }
        ],
        "dynsym": [
            {
                "name": "main",
                "value": 0x401000,
                "size": 16,
                "type": "FUNC",
                "binding": "GLOBAL",
                "visibility": "DEFAULT",
                "shndx": 1,
            }
        ],
    }
