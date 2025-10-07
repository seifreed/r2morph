"""
Unit tests for Binary class.
"""

from unittest.mock import MagicMock, patch

import pytest

from r2morph.core.binary import Binary


class TestBinary:
    """Tests for the Binary class."""

    def test_binary_init_with_nonexistent_file(self):
        """Test that initializing with non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            Binary("/path/to/nonexistent/binary")

    @patch("r2morph.core.binary.r2pipe")
    def test_binary_open_and_close(self, mock_r2pipe, tmp_path):
        """Test opening and closing a binary."""
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"\x00" * 100)

        mock_r2 = MagicMock()
        mock_r2.cmdj.return_value = {"bin": {"arch": "x86", "bits": 64}}
        mock_r2pipe.open.return_value = mock_r2

        binary = Binary(test_file)
        binary.open()

        assert binary.r2 is not None
        mock_r2pipe.open.assert_called_once()

        binary.close()
        mock_r2.quit.assert_called_once()

    @patch("r2morph.core.binary.r2pipe")
    def test_binary_context_manager(self, mock_r2pipe, tmp_path):
        """Test using Binary as a context manager."""
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"\x00" * 100)

        mock_r2 = MagicMock()
        mock_r2.cmdj.return_value = {"bin": {"arch": "x86", "bits": 64}}
        mock_r2pipe.open.return_value = mock_r2

        with Binary(test_file) as binary:
            assert binary.r2 is not None

        mock_r2.quit.assert_called_once()

    @patch("r2morph.core.binary.r2pipe")
    def test_binary_analyze(self, mock_r2pipe, tmp_path):
        """Test binary analysis."""
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"\x00" * 100)

        mock_r2 = MagicMock()
        mock_r2.cmdj.return_value = {"bin": {"arch": "x86", "bits": 64}}
        mock_r2pipe.open.return_value = mock_r2

        with Binary(test_file) as binary:
            binary.analyze("aaa")
            mock_r2.cmd.assert_called_with("aaa")
            assert binary.is_analyzed()

    @patch("r2morph.core.binary.r2pipe")
    def test_get_functions(self, mock_r2pipe, tmp_path):
        """Test getting functions from binary."""
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"\x00" * 100)

        mock_r2 = MagicMock()
        mock_r2.cmdj.side_effect = [
            {"bin": {"arch": "x86", "bits": 64}},
            [{"name": "main", "offset": 0x1000, "size": 100}],
        ]
        mock_r2pipe.open.return_value = mock_r2

        with Binary(test_file) as binary:
            functions = binary.get_functions()
            assert len(functions) == 1
            assert functions[0]["name"] == "main"

    @patch("r2morph.core.binary.r2pipe")
    def test_get_arch_info(self, mock_r2pipe, tmp_path):
        """Test getting architecture information."""
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"\x00" * 100)

        mock_r2 = MagicMock()
        mock_r2.cmdj.return_value = {
            "bin": {
                "arch": "x86",
                "bits": 64,
                "endian": "little",
                "class": "ELF",
                "machine": "AMD x86-64 architecture",
            }
        }
        mock_r2pipe.open.return_value = mock_r2

        with Binary(test_file) as binary:
            arch_info = binary.get_arch_info()
            assert arch_info["arch"] == "x86"
            assert arch_info["bits"] == 64
            assert arch_info["endian"] == "little"
