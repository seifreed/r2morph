from pathlib import Path

import pytest

from r2morph.adapters.disassembler import DisassemblerInterface
from r2morph.adapters.r2pipe_adapter import R2PipeAdapter


def test_r2pipe_adapter_open_and_commands():
    adapter = R2PipeAdapter()
    binary_path = Path("dataset/elf_x86_64")

    adapter.open(binary_path, flags=["-2"])
    assert adapter.is_open() is True

    info = adapter.cmdj("ij")
    assert isinstance(info, dict)
    assert "bin" in info

    funcs = adapter.cmdj("aflj")
    assert isinstance(funcs, list)

    adapter.close()
    assert adapter.is_open() is False


def test_r2pipe_adapter_errors_and_protocol():
    adapter = R2PipeAdapter()
    assert isinstance(adapter, DisassemblerInterface)

    with pytest.raises(RuntimeError):
        adapter.cmd("ij")

    with pytest.raises(RuntimeError):
        adapter.cmdj("ij")

    with pytest.raises(FileNotFoundError):
        adapter.open(Path("does_not_exist.bin"))
