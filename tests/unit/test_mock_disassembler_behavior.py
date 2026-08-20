from pathlib import Path

import pytest

from r2morph.adapters.mock_disassembler import MockDisassembler
from r2morph.protocols import DisassemblerInterface
from tests.utils.assertions import expect


def test_mock_disassembler_open_close_and_history(tmp_path):
    mock = MockDisassembler(
        responses={
            "ij": {"bin": {"arch": "x86", "bits": 64}},
            "aflj": [{"name": "main", "offset": 0x1000}],
        }
    )

    binary_path = tmp_path / "binary"
    binary_path.write_text("stub")

    mock.open(binary_path, flags=["-2"])
    expect(not (mock.is_open() is not True))
    expect(mock.opened_path == binary_path)
    expect(mock.opened_flags == ["-2"])

    expect(mock.cmdj("ij")["bin"]["arch"] == "x86")
    expect(mock.cmd("aflj") == str([{"name": "main", "offset": 4096}]))
    expect(mock.command_history == ["ij", "aflj"])

    mock.assert_command_called("ij")
    mock.assert_command_not_called("aaa")

    mock.close()
    expect(not (mock.is_open() is not False))


def test_mock_disassembler_errors_and_resets():
    mock = MockDisassembler()

    with pytest.raises(RuntimeError):
        mock.cmd("ij")
    with pytest.raises(RuntimeError):
        mock.cmdj("ij")

    mock.open(Path("/fake/binary"))
    mock.set_response("ij", {"bin": {"arch": "arm"}})
    expect(mock.cmdj("ij")["bin"]["arch"] == "arm")

    mock.clear_responses()
    expect(mock.cmdj("ij") == {})


def test_mock_disassembler_protocol_runtime_check():
    mock = MockDisassembler()
    expect(isinstance(mock, DisassemblerInterface))
