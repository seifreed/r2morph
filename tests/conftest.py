"""
Pytest configuration and fixtures.
"""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def sample_binary(tmp_path):
    """
    Create a sample binary file for testing.

    Returns:
        Path to the temporary binary file
    """
    binary_file = tmp_path / "test_binary"
    binary_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    return binary_file


@pytest.fixture
def mock_r2():
    """
    Create a mock r2pipe instance.

    Returns:
        MagicMock configured to simulate r2pipe behavior
    """
    mock = MagicMock()
    mock.cmdj.return_value = {
        "bin": {
            "arch": "x86",
            "bits": 64,
            "endian": "little",
            "class": "ELF",
        }
    }
    return mock


@pytest.fixture
def sample_function_data():
    """
    Sample function data as returned by radare2.

    Returns:
        Dictionary with function metadata
    """
    return {
        "offset": 0x1000,
        "name": "sym.main",
        "size": 150,
        "callrefs": [0x2000, 0x3000],
        "type": "fcn",
    }


@pytest.fixture
def sample_instruction_data():
    """
    Sample instruction data as returned by radare2.

    Returns:
        Dictionary with instruction metadata
    """
    return {
        "offset": 0x1000,
        "disasm": "mov eax, 0x1",
        "bytes": "b801000000",
        "size": 5,
        "type": "mov",
    }


@pytest.fixture
def sample_functions_list():
    """
    Sample list of functions for testing.

    Returns:
        List of function dictionaries
    """
    return [
        {
            "offset": 0x1000,
            "name": "sym.main",
            "size": 150,
            "callrefs": [],
        },
        {
            "offset": 0x2000,
            "name": "sym.helper",
            "size": 80,
            "callrefs": [],
        },
        {
            "offset": 0x3000,
            "name": "sym.process",
            "size": 200,
            "callrefs": [0x1000],
        },
    ]
