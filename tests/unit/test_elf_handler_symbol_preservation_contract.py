import sys
from pathlib import Path
from types import SimpleNamespace

from r2morph.platform.elf_handler_symbol_preservation import preserve_symbols


def test_elf_handler_symbol_preservation_contract(monkeypatch, tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.elf"
    binary_path.write_bytes(b"\x7fELF" + b"\x00" * 64)

    fake_binary = SimpleNamespace(static_symbols=[1, 2], dynamic_symbols=[3])
    fake_lief = SimpleNamespace(parse=lambda _: fake_binary)
    monkeypatch.setitem(sys.modules, "lief", fake_lief)

    assert preserve_symbols(binary_path) is True
