"""Tests demonstrating DIP: mutation passes work with mock disassembler."""
import pytest
from unittest.mock import MagicMock
from r2morph.adapters.disassembler import DisassemblerInterface


class MockDisassembler:
    """Mock implementing DisassemblerInterface for testing without r2pipe."""
    def __init__(self):
        self._open = False
    def open(self, path, flags=None): self._open = True
    def close(self): self._open = False
    def cmd(self, command): return ""
    def cmdj(self, command): return {}
    def is_open(self): return self._open


def test_mock_satisfies_protocol():
    mock = MockDisassembler()
    assert isinstance(mock, DisassemblerInterface)


def test_binary_accepts_mock_disassembler():
    from r2morph.core.binary import Binary
    import tempfile, os
    # Create a minimal temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        f.write(b'\x00' * 64)
        tmp = f.name
    try:
        mock = MockDisassembler()
        binary = Binary(tmp, disassembler=mock)
        binary.open()
        assert binary.r2 is mock
    finally:
        os.unlink(tmp)
