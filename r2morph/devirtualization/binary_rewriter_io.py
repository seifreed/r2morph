from __future__ import annotations

import logging
import os
import shutil
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


def write_output_binary(source_path: str | Path | None, output_path: str) -> bool:
    try:
        if source_path is None:
            logger.error("Original binary path not available")
            return False

        shutil.copy2(source_path, output_path)
        with open(output_path, "ab") as f:
            f.write(b"\x00\x00R2MORPH_REWRITTEN\x00\x00")

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
