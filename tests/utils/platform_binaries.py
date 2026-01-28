from __future__ import annotations

import platform
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _ROOT / "tests" / "fixtures"
_DATASET = _ROOT / "dataset"


def get_platform_binary(kind: str = "generic") -> Path:
    """
    Return a platform-appropriate binary for integration tests.

    kind values:
      - simple/loop/conditional: prefer fixtures on macOS, fallback to dataset on others
      - generic: prefer dataset per-OS
    """
    system = platform.system()

    if system == "Darwin":
        if kind in {"simple", "loop", "conditional"}:
            return _FIXTURES / kind
        return _DATASET / "macho_arm64"

    if system == "Windows":
        return _DATASET / "pe_x86_64.exe"

    # Linux/other Unix
    return _DATASET / "elf_x86_64"


def ensure_exists(path: Path) -> bool:
    return path.exists()
