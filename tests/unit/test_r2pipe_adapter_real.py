from pathlib import Path

import pytest

from r2morph.adapters.r2pipe_adapter import R2PipeAdapter
from r2morph.protocols import DisassemblerInterface
from tests.utils.assertions import expect


def test_r2pipe_adapter_open_and_commands():
    adapter = R2PipeAdapter()
    binary_path = Path("fixtures/dataset/elf_x86_64")

    adapter.open(binary_path, flags=["-2"])
    expect(not (adapter.is_open() is not True))

    info = adapter.cmdj("ij")
    expect(isinstance(info, dict))
    expect(not ("bin" not in info))

    funcs = adapter.cmdj("aflj")
    expect(isinstance(funcs, list))

    adapter.close()
    expect(not (adapter.is_open() is not False))


def test_r2pipe_adapter_errors_and_protocol():
    adapter = R2PipeAdapter()
    expect(isinstance(adapter, DisassemblerInterface))

    with pytest.raises(RuntimeError):
        adapter.cmd("ij")

    with pytest.raises(RuntimeError):
        adapter.cmdj("ij")

    with pytest.raises(FileNotFoundError):
        adapter.open(Path("does_not_exist.bin"))
