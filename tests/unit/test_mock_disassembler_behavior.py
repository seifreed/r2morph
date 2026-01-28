from pathlib import Path

import pytest

from r2morph.adapters.disassembler import DisassemblerInterface
from r2morph.adapters.mock_disassembler import MockDisassembler


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
    assert mock.is_open() is True
    assert mock.opened_path == binary_path
    assert mock.opened_flags == ["-2"]

    assert mock.cmdj("ij")["bin"]["arch"] == "x86"
    assert mock.cmd("aflj") == str([{"name": "main", "offset": 0x1000}])
    assert mock.command_history == ["ij", "aflj"]

    mock.assert_command_called("ij")
    mock.assert_command_not_called("aaa")

    mock.close()
    assert mock.is_open() is False


def test_mock_disassembler_errors_and_resets():
    mock = MockDisassembler()

    with pytest.raises(RuntimeError):
        mock.cmd("ij")
    with pytest.raises(RuntimeError):
        mock.cmdj("ij")

    mock.open(Path("/fake/binary"))
    mock.set_response("ij", {"bin": {"arch": "arm"}})
    assert mock.cmdj("ij")["bin"]["arch"] == "arm"

    mock.clear_responses()
    assert mock.cmdj("ij") == {}


def test_mock_disassembler_protocol_runtime_check():
    mock = MockDisassembler()
    assert isinstance(mock, DisassemblerInterface)
