from pathlib import Path

from r2morph.devirtualization.binary_rewriter import BinaryFormat, BinaryRewriter
from r2morph.devirtualization.binary_rewriter_io import (
    create_backup,
    perform_integrity_checks,
    write_output_binary,
)
from tests.utils.assertions import expect


def test_binary_rewriter_io_helpers_expose_expected_contract(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"\x7fELF" + b"\x00" * 60)
    output = tmp_path / "output.bin"

    create_backup(source)
    expect(source.with_suffix(source.suffix + ".backup").exists())

    expect(not (write_output_binary(source, str(output)) is not True))
    expect(output.exists())
    expect(output.read_bytes().endswith(b"R2MORPH_REWRITTEN\x00\x00"))

    checks = perform_integrity_checks(BinaryFormat.ELF, str(output))
    expect(not (checks["file_exists"] is not True))
    expect(not (checks["valid_pe_header"] is not True))
    expect(not (checks["imports_intact"] is not False))
    expect(not (checks["exports_intact"] is not False))
    expect(not (checks["entry_point_valid"] is not False))

    rewriter = BinaryRewriter()
    rewriter.binary = type("BinaryStub", (), {"filepath": source})()
    expect(not (rewriter._write_output_binary(str(tmp_path / "writer.bin")) is not True))
