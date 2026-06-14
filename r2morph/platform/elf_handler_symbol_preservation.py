"""Symbol preservation helpers for ELF handlers."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def preserve_symbols(binary_path: Path) -> bool:
    """Check whether symbol tables are still readable after a mutation."""
    try:
        import lief
    except ImportError:
        logger.warning("lief library required for symbol preservation. Install with: pip install lief")
        return False

    try:
        elf = lief.parse(str(binary_path))
        if elf is None:
            logger.error(f"Failed to parse ELF for symbol preservation: {binary_path}")
            return False

        if hasattr(elf, "static_symbols"):
            static_symbols = list(elf.static_symbols)
        else:
            static_symbols = list(getattr(elf, "symbols", []))

        if hasattr(elf, "dynamic_symbols"):
            dynamic_symbols = list(elf.dynamic_symbols)
        else:
            dynamic_symbols = list(getattr(elf, "dynamic_symbols", []))

        logger.info(f"Symbol tables intact: {len(static_symbols)} static, {len(dynamic_symbols)} dynamic symbols")
        return True
    except Exception as exc:
        logger.error(f"Symbol preservation check failed: {exc}")
        return False


__all__ = ["preserve_symbols"]
