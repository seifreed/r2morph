from pathlib import Path

from r2morph.core.writer import BinaryWriter
from tests._doubles.scripted_r2_binary import ScriptedR2Binary


def test_binary_writer_verified_disassembler_write_increments_counter(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 8)
    scripted = ScriptedR2Binary({"p8": "90"})
    writer = BinaryWriter(scripted.r2, binary_path, writable=True)

    assert writer.write_bytes(0x1000, b"\x90") is True
    assert writer.get_mutation_counter() == 1


def test_binary_writer_failed_disassembler_write_uses_resolved_file_offset(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 8)
    scripted = ScriptedR2Binary({"p8": "00"})
    writer = BinaryWriter(scripted.r2, binary_path, writable=True)

    assert writer.write_bytes(0x1000, b"\x90", lambda _address: 3) is True
    assert binary_path.read_bytes()[3] == 0x90


def test_binary_writer_rejects_write_outside_known_sections(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 8)
    scripted = ScriptedR2Binary({"p8": "90"})
    writer = BinaryWriter(scripted.r2, binary_path, writable=True)

    assert writer.write_bytes(0x2000, b"\x90", sections=[{"vaddr": 0x1000, "vsize": 8}]) is False
    assert writer.get_mutation_counter() == 0
