from pathlib import Path

import pytest

from r2morph.adapters.r2pipe_adapter import R2PipeAdapter


def test_r2pipe_adapter_open_cmd_close():
    adapter = R2PipeAdapter()
    assert adapter.is_open() is False

    binary_path = Path("dataset/elf_x86_64")
    adapter.open(binary_path, flags=["-2"])
    assert adapter.is_open() is True

    info = adapter.cmdj("ij")
    assert isinstance(info, dict)
    assert "bin" in info

    adapter.close()
    assert adapter.is_open() is False

    with pytest.raises(RuntimeError):
        adapter.cmd("ij")
