"""Runtime execution helpers for binary validation."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from r2morph.adapters.process import ProcessContext, ProcessTimeoutError, run_process
from r2morph.validation.validator_execution_files import collect_monitored_files
from r2morph.validation.validator_runtime import ValidationTestCase

logger = logging.getLogger(__name__)


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
        except (OSError, PermissionError) as exc:
            logger.debug("Could not mark runtime binary executable: %s", exc)

        if test_case.working_dir:
            run_dir = Path(test_case.working_dir)
        else:
            run_dir = Path(tempfile.mkdtemp(prefix="r2morph_runtime_"))
            cleanup_dir = True

        run_dir.mkdir(parents=True, exist_ok=True)

        local_binary = run_dir / binary_path.name
        shutil.copy2(binary_path, local_binary)
        cmd = [str(local_binary), *test_case.args]

        result = run_process(
            cmd,
            timeout=timeout,
            context=ProcessContext(
                input_bytes=test_case.stdin.encode() if test_case.stdin else None,
                env={**os.environ, **test_case.env},
                cwd=run_dir,
            ),
        )

        return {
            "stdout": result.stdout_text,
            "stderr": result.stderr_text,
            "exitcode": result.returncode,
            "files": collect_monitored_files(run_dir, test_case.monitored_files),
        }

    except ProcessTimeoutError:
        return {"stdout": "", "stderr": "Timeout", "exitcode": -1, "files": {}}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "exitcode": -1, "files": {}}
    finally:
        if cleanup_dir and run_dir and run_dir.exists():
            try:
                shutil.rmtree(run_dir)
            except OSError as exc:
                logger.debug("Could not remove runtime directory: %s", exc)
