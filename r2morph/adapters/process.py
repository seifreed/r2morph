"""Shell-free external process execution."""

from __future__ import annotations

import asyncio
import os
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


class ProcessError(RuntimeError):
    """Base error for external process execution."""


class ProcessTimeoutError(ProcessError):
    """Raised when an external process exceeds its timeout."""


class ProcessExecutionError(ProcessError):
    """Raised when a checked process returns a non-zero status."""


@dataclass(frozen=True)
class ProcessResult:
    """Captured external process result."""

    stdout: bytes
    stderr: bytes
    returncode: int

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode(errors="replace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode(errors="replace")


@dataclass(frozen=True)
class ProcessContext:
    """Optional input and execution context for a process."""

    input_bytes: bytes | None = None
    env: Mapping[str, str] | None = None
    cwd: str | Path | None = None


def _resolve_executable(value: str | Path) -> str:
    executable = os.fspath(value)
    has_separator = os.sep in executable or bool(os.altsep and os.altsep in executable)
    if has_separator:
        path = Path(executable).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Executable not found: {path.name}")
        return str(path)
    resolved = shutil.which(executable)
    if resolved is None:
        raise FileNotFoundError(f"Executable not found: {executable}")
    return resolved


async def _run_process(
    command: Sequence[str | Path],
    *,
    timeout: float | None,
    context: ProcessContext,
) -> ProcessResult:
    if not command:
        raise ValueError("Process command cannot be empty")
    executable = _resolve_executable(command[0])
    arguments = [executable, *(os.fspath(value) for value in command[1:])]
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.PIPE if context.input_bytes is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=context.env,
        cwd=context.cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(context.input_bytes), timeout)
    except TimeoutError:
        process.kill()
        await process.communicate()
        raise ProcessTimeoutError(f"Process exceeded {timeout} seconds") from None
    return ProcessResult(stdout=stdout, stderr=stderr, returncode=process.returncode or 0)


def run_process(
    command: Sequence[str | Path],
    *,
    timeout: float | None = None,
    context: ProcessContext | None = None,
    check: bool = False,
) -> ProcessResult:
    """Run an external command without a shell and capture its output."""
    result = asyncio.run(_run_process(command, timeout=timeout, context=context or ProcessContext()))
    if check and result.returncode != 0:
        raise ProcessExecutionError(f"Process exited with status {result.returncode}")
    return result
