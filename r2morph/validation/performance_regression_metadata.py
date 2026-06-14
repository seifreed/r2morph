"""Runtime metadata helpers for performance regression snapshots."""

from __future__ import annotations

import platform
import subprocess
import sys


def get_git_hash() -> str:
    """Return the current git commit hash or a safe fallback."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()[:12]
    except Exception:
        return "unknown"


def get_cpu_count() -> int:
    """Return the detected CPU count, defaulting to 1."""
    try:
        import os

        return os.cpu_count() or 1
    except Exception:
        return 1


def get_environment_info() -> dict[str, str]:
    """Collect the platform details used in benchmark snapshots."""
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.system(),
        "platform_version": platform.version(),
        "cpu_count": str(get_cpu_count()),
        "machine": platform.machine(),
    }
