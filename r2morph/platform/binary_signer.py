"""Post-save binary signing and repair for the host platform."""

import logging
import platform
from pathlib import Path
from typing import Any

from r2morph.platform.codesign import CodeSigner
from r2morph.platform.macho_handler import MachOHandler

logger = logging.getLogger(__name__)


class DarwinBinarySigner:
    """Sign/repair saved binaries on macOS; a no-op on other platforms."""

    def sign_output(self, output_path: Path, config: dict[str, Any]) -> None:
        if platform.system() != "Darwin":
            return

        entitlements = config.get("codesign_entitlements")
        if entitlements:
            entitlements = Path(entitlements)
        hardened = bool(config.get("codesign_hardened", False))
        timestamp = bool(config.get("codesign_timestamp", False))

        handler = MachOHandler(output_path)
        if handler.is_macho():
            ok, msg = handler.validate_integrity()
            if not ok:
                logger.warning(f"Mach-O layout check failed: {msg}")
            repaired = handler.repair_integrity(
                entitlements=entitlements,
                hardened=hardened,
                timestamp=timestamp,
            )
            if not repaired:
                logger.warning(f"Mach-O repair/signing failed for: {output_path}")
            try:
                output_path.chmod(output_path.stat().st_mode | 0o111)
            except OSError as e:
                logger.warning(f"Failed to mark Mach-O executable: {e}")
        else:
            signer = CodeSigner()
            if not signer.sign_binary(
                output_path,
                adhoc=True,
                entitlements=entitlements,
                hardened=hardened,
                timestamp=timestamp,
            ):
                logger.warning(f"Ad-hoc signing failed for: {output_path}")
