"""Synchronous test adapter for the production process runner."""

from __future__ import annotations

import os
import subprocess
import sys
import sysconfig
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from r2morph.adapters.process import ProcessContext, run_process


def python_runtime_environment() -> dict[str, str]:
    environment = os.environ.copy()
    if sys.platform == "darwin":
        library_directory = sysconfig.get_config_var("LIBDIR")
        if isinstance(library_directory, str) and library_directory:
            existing_library_path = environment.get("DYLD_LIBRARY_PATH")
            environment["DYLD_LIBRARY_PATH"] = os.pathsep.join(
                value for value in (library_directory, existing_library_path) if value
            )
    return environment


def run_command(
    command: Sequence[str | Path],
    **options: Any,
) -> subprocess.CompletedProcess[Any]:
    """Expose production process semantics through a CompletedProcess result."""
    options.pop("capture_output", False)
    text = bool(options.pop("text", False))
    timeout = options.pop("timeout", None)
    check = bool(options.pop("check", False))
    env = options.pop("env", None)
    cwd = options.pop("cwd", None)
    start_new_session = bool(options.pop("start_new_session", True))
    input = options.pop("input", None)
    if options:
        unexpected = ", ".join(sorted(options))
        raise TypeError(f"Unsupported process options: {unexpected}")
    input_bytes = input.encode() if isinstance(input, str) else input
    result = run_process(
        command,
        timeout=timeout,
        context=ProcessContext(
            input_bytes=input_bytes,
            env=env,
            cwd=cwd,
            start_new_session=start_new_session,
        ),
    )
    stdout: str | bytes = result.stdout_text if text else result.stdout
    stderr: str | bytes = result.stderr_text if text else result.stderr
    completed = subprocess.CompletedProcess(
        [os.fspath(value) for value in command],
        result.returncode,
        stdout,
        stderr,
    )
    if check and completed.returncode:
        raise subprocess.CalledProcessError(
            completed.returncode,
            completed.args,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return completed
