from pathlib import Path

from r2morph.devirtualization.binary_rewriter import BinaryFormat, BinaryRewriter
from r2morph.devirtualization.binary_rewriter_io import (
    create_backup,
    perform_integrity_checks,
    write_output_binary,
)


def test_binary_rewriter_io_helpers_expose_expected_contract(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"\x7fELF" + b"\x00" * 60)
    output = tmp_path / "output.bin"

    create_backup(source)
    assert source.with_suffix(source.suffix + ".backup").exists()

    assert write_output_binary(source, str(output)) is True
    assert output.exists()
    assert output.read_bytes().endswith(b"R2MORPH_REWRITTEN\x00\x00")

    checks = perform_integrity_checks(BinaryFormat.ELF, str(output))
    assert checks["file_exists"] is True
    assert checks["valid_pe_header"] is True
    assert checks["imports_intact"] is False
    assert checks["exports_intact"] is False
    assert checks["entry_point_valid"] is False

    rewriter = BinaryRewriter()
    rewriter.binary = type("BinaryStub", (), {"filepath": source})()
    assert rewriter._write_output_binary(str(tmp_path / "writer.bin")) is True
