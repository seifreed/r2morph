"""Tests demonstrating DIP: mutation passes work with mock disassembler."""

import importlib

from r2morph.protocols import DisassemblerInterface
from tests.utils.assertions import expect


class MockDisassembler:
    """Mock implementing DisassemblerInterface for testing without r2pipe."""

    def __init__(self):
        self._open = False

    def open(self, path, flags=None):
        self._open = True

    def close(self):
        self._open = False

    def cmd(self, command):
        return ""

    def cmdj(self, command):
        return {}

    def is_open(self):
        return self._open


def test_mock_satisfies_protocol():
    mock = MockDisassembler()
    expect(isinstance(mock, DisassemblerInterface))


def test_binary_accepts_mock_disassembler():
    os = importlib.import_module("os")
    tempfile = importlib.import_module("tempfile")

    binary = importlib.import_module("r2morph.core.binary").Binary

    # Create a minimal temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x00" * 64)
        tmp = f.name
    try:
        mock = MockDisassembler()
        binary = binary(tmp, disassembler=mock)
        binary.open()
        expect(not (binary.r2 is not mock))
    finally:
        os.unlink(tmp)
