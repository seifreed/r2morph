from __future__ import annotations

import platform
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _ROOT / "fixtures" / "synthetic"
_DATASET = _ROOT / "fixtures" / "dataset"
_NATIVE_ELF_MACHINES = frozenset({"amd64", "x86_64"})


def supports_native_elf_x86_64(system: str | None = None, machine: str | None = None) -> bool:
    """Return whether the host can execute the official ELF x86-64 target."""
    host_system = system or platform.system()
    host_machine = (machine or platform.machine()).lower()
    return host_system == "Linux" and host_machine in _NATIVE_ELF_MACHINES


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
