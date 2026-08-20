from pathlib import Path

import pytest

from r2morph.adapters.r2pipe_adapter import R2PipeAdapter
from tests.utils.assertions import expect


def test_r2pipe_adapter_open_cmd_close():
    adapter = R2PipeAdapter()
    expect(not (adapter.is_open() is not False))

    binary_path = Path("fixtures/dataset/elf_x86_64")
    adapter.open(binary_path, flags=["-2"])
    expect(not (adapter.is_open() is not True))

    info = adapter.cmdj("ij")
    expect(isinstance(info, dict))
    expect(not ("bin" not in info))

    adapter.close()
    expect(not (adapter.is_open() is not False))

    with pytest.raises(RuntimeError):
        adapter.cmd("ij")
