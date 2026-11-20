from __future__ import annotations

import logging
import os
import shutil
import tempfile
from pathlib import Path

from r2morph.devirtualization.binary_rewriter_models import BinaryFormat

logger = logging.getLogger(__name__)


def create_backup(source_path: str | Path | None) -> None:
    if source_path is None:
        return

    try:
        backup_path = f"{source_path}.backup"
        shutil.copy2(source_path, backup_path)
        logger.info("Created backup at %s", backup_path)
    except Exception as e:
        logger.warning("Failed to create backup: %s", e)


def write_output_binary(source_path: str | Path | None, output_path: str, data: bytes | None = None) -> bool:
    try:
        if source_path is None:
            logger.error("Original binary path not available")
            return False

        source = Path(source_path).resolve()
        destination = Path(output_path)
        if source == destination.resolve():
            logger.error("Refusing to overwrite the original binary")
            return False

        contents = source.read_bytes() if data is None else data
        if len(contents) != source.stat().st_size:
            logger.error("Refusing to write output with a different file size")
            return False
        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=destination.parent,
                prefix=f".{destination.name}.",
                delete=False,
            ) as out:
                temporary_path = out.name
                out.write(contents)
            shutil.copystat(source, temporary_path)
            os.replace(temporary_path, destination)
        finally:
            if temporary_path is not None and os.path.exists(temporary_path):
                os.unlink(temporary_path)

        logger.info("Written rewritten binary to %s", output_path)
        return True
    except Exception as e:
        logger.error("Failed to write output binary: %s", e)
        return False


def perform_integrity_checks(binary_format: BinaryFormat, output_path: str) -> dict[str, bool]:
    checks = {
        "file_exists": False,
        "valid_pe_header": False,
        "imports_intact": False,
        "exports_intact": False,
        "entry_point_valid": False,
    }

    try:
        checks["file_exists"] = os.path.exists(output_path)

        if checks["file_exists"]:
            with open(output_path, "rb") as f:
                header = f.read(64)

            if binary_format == BinaryFormat.PE:
                checks["valid_pe_header"] = header.startswith(b"MZ")
            elif binary_format == BinaryFormat.ELF:
                checks["valid_pe_header"] = header.startswith(b"\x7fELF")
            else:
                checks["valid_pe_header"] = True

    except OSError as e:
        logger.error("Integrity check I/O failure for %s: %s", output_path, e)

    return checks
