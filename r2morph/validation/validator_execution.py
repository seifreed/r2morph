"""Runtime execution helpers for binary validation."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from r2morph.validation.validator_execution_files import collect_monitored_files
from r2morph.validation.validator_execution_text import hash_text, normalize_output  # noqa: F401
from r2morph.validation.validator_runtime import ValidationTestCase


def run_binary(binary_path: Path, test_case: ValidationTestCase, timeout: int) -> dict[str, Any]:
    """
    Run a binary and capture output.

    Args:
        binary_path: Path to binary
        test_case: Test case configuration
        timeout: Maximum runtime in seconds

    Returns:
        Dict with stdout, stderr, exitcode
    """
    run_dir = None
    cleanup_dir = False

    try:
        try:
            binary_path.chmod(0o755)
        except (OSError, PermissionError):
            # Best-effort chmod; some filesystems/permissions disallow it and execution still proceeds without it.
            pass

        if test_case.working_dir:
            run_dir = Path(test_case.working_dir)
        else:
            run_dir = Path(tempfile.mkdtemp(prefix="r2morph_runtime_"))
            cleanup_dir = True

        run_dir.mkdir(parents=True, exist_ok=True)

        local_binary = run_dir / binary_path.name
        shutil.copy2(binary_path, local_binary)
        cmd = [str(local_binary)] + test_case.args

        result = subprocess.run(
            cmd,
            input=test_case.stdin.encode() if test_case.stdin else None,
            capture_output=True,
            timeout=timeout,
            env={**os.environ, **test_case.env},
            cwd=run_dir,
        )

        return {
            "stdout": result.stdout.decode(errors="replace"),
            "stderr": result.stderr.decode(errors="replace"),
            "exitcode": result.returncode,
            "files": collect_monitored_files(run_dir, test_case.monitored_files),
        }

    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "exitcode": -1, "files": {}}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "exitcode": -1, "files": {}}
    finally:
        if cleanup_dir and run_dir and run_dir.exists():
            try:
                shutil.rmtree(run_dir)
            except Exception:
                pass
