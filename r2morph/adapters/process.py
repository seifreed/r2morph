"""Shell-free external process execution."""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import shutil
import signal
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from r2morph.utils.logging import observed_operation

logger = logging.getLogger(__name__)


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
    """Optional process context for child process execution."""

    input_bytes: bytes | None = None
    env: Mapping[str, str] | None = None
    cwd: str | Path | None = None


def _resolve_executable(value: str | Path) -> str:
    executable = os.fspath(value)
    has_separator = os.sep in executable or bool(os.altsep and os.altsep in executable)
    if has_separator:
        path = Path(executable).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"Executable not found: {path.name}")
        return str(path)
    resolved = shutil.which(executable)
    if resolved is None:
        raise FileNotFoundError(f"Executable not found: {executable}")
    return resolved


def _build_arguments(command: Sequence[str | Path]) -> list[str]:
    executable = _resolve_executable(command[0])
    arguments = [executable, *(os.fspath(value) for value in command[1:])]
    try:
        with Path(executable).open("rb") as script_file:
            first_line = script_file.readline(4096)
    except OSError:
        return arguments
    if not first_line.startswith(b"#!"):
        return arguments
    interpreter = shlex.split(first_line[2:].decode("utf-8", errors="replace"))
    return [*interpreter, executable, *arguments[1:]] if interpreter else arguments


async def _run_process(
    command: Sequence[str | Path],
    *,
    timeout: float | None,
    context: ProcessContext,
) -> ProcessResult:
    if not command:
        raise ValueError("Process command cannot be empty")
    arguments = _build_arguments(command)
    with ExitStack() as temporary_files:
        stdout_file = temporary_files.enter_context(tempfile.TemporaryFile())
        stderr_file = temporary_files.enter_context(tempfile.TemporaryFile())
        stdin_file = None
        if context.input_bytes is not None:
            stdin_file = temporary_files.enter_context(tempfile.TemporaryFile())
            stdin_file.write(context.input_bytes)
            stdin_file.seek(0)
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdin=stdin_file,
            stdout=stdout_file,
            stderr=stderr_file,
            env=context.env,
            cwd=context.cwd,
            start_new_session=os.name == "posix",
        )
        try:
            await asyncio.wait_for(process.wait(), timeout)
        except TimeoutError:
            await _terminate_process_tree(process)
            raise ProcessTimeoutError(f"Process exceeded {timeout} seconds") from None
        stdout_file.seek(0)
        stderr_file.seek(0)
        return ProcessResult(
            stdout=stdout_file.read(),
            stderr=stderr_file.read(),
            returncode=process.returncode or 0,
        )


async def _terminate_process_tree(
    process: asyncio.subprocess.Process,
) -> None:
    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    else:
        try:
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/PID",
                str(process.pid),
                "/T",
                "/F",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await killer.wait()
            if killer.returncode != 0:
                _kill_if_running(process)
        except OSError:
            _kill_if_running(process)
    transport = cast(Any, process)._transport
    for file_descriptor in (1, 2):
        pipe_transport = transport.get_pipe_transport(file_descriptor)
        if pipe_transport is not None:
            # asyncio.Process has no public way to close pipes held by descendants.
            pipe_transport.close()
    await process.wait()


def _kill_if_running(process: asyncio.subprocess.Process) -> None:
    if process.returncode is None:
        with suppress(ProcessLookupError):
            # The child can exit between taskkill's result and the fallback kill.
            process.kill()


def run_process(
    command: Sequence[str | Path],
    *,
    timeout: float | None = None,
    context: ProcessContext | None = None,
    check: bool = False,
) -> ProcessResult:
    """Run an external command without a shell and capture its output."""
    with observed_operation(logger, "process.execute", event_name="process.execute"):
        result = asyncio.run(_run_process(command, timeout=timeout, context=context or ProcessContext()))
        if check and result.returncode != 0:
            raise ProcessExecutionError(f"Process exited with status {result.returncode}")
        return result
