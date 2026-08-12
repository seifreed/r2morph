"""Runtime metadata helpers for performance regression snapshots."""

from __future__ import annotations

import os
import platform
import sys

from r2morph.adapters.process import run_process


def get_git_hash() -> str:
    """Return the current git commit hash or a safe fallback."""
    try:
        result = run_process(["git", "rev-parse", "HEAD"], check=True)
        return result.stdout_text.strip()[:12]
    except Exception:
        return "unknown"


def get_cpu_count() -> int:
    """Return the detected CPU count, defaulting to 1."""
    try:
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
