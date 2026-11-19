"""Real-process contract for the external process adapter."""

import asyncio
import os
import shutil
import signal
import sys
import time
from contextlib import suppress
from pathlib import Path

import pytest

from r2morph.adapters.process import (
    ProcessContext,
    ProcessTimeoutError,
    _resolve_executable,
    _terminate_process_tree,
    run_process,
)
from tests.utils.assertions import expect
from tests.utils.process import python_runtime_environment

_DETACHED_PIPE_CLEANUP_LIMIT_SECONDS = 2.5


def test_run_process_captures_stdout() -> None:
    result = run_process([Path(sys.executable), "-c", "print('ok')"], check=True)

    expect(result.stdout_text.strip() == "ok")


def test_run_process_respects_context_process_session_choice() -> None:
    result = run_process(
        [Path(sys.executable), "-c", "import os; print(os.getsid(0) if hasattr(os, 'getsid') else 'ok')"],
        context=ProcessContext(start_new_session=False),
        check=True,
    )

    expected = str(os.getsid(0)) if hasattr(os, "getsid") else "ok"
    expect(result.stdout_text.strip() == expected)


def test_run_process_timeout_kills_child_without_a_new_session() -> None:
    started = time.monotonic()
    with pytest.raises(ProcessTimeoutError):
        run_process(
            [Path(sys.executable), "-c", "import time; time.sleep(30)"],
            timeout=0.1,
            context=ProcessContext(start_new_session=False),
        )

    expect(time.monotonic() - started < _DETACHED_PIPE_CLEANUP_LIMIT_SECONDS)


def test_resolve_executable_preserves_symlink_driver_name(tmp_path: Path) -> None:
    executable_alias = tmp_path / "python-alias"
    executable_alias.symlink_to(sys.executable)

    expect(_resolve_executable(executable_alias) == str(executable_alias))


def test_run_process_executes_copied_interpreter_without_a_shell(tmp_path: Path) -> None:
    executable = tmp_path / Path(sys.executable).name
    shutil.copy2(sys.executable, executable)

    result = run_process(
        [executable, "-c", "print('ok')"],
        context=ProcessContext(env=python_runtime_environment()),
        check=True,
    )

    expect(result.stdout_text.strip() == "ok")


def test_run_process_timeout_terminates_descendant_processes(tmp_path: Path) -> None:
    marker = tmp_path / "child-survived"
    child_code = "import pathlib, time; " f"time.sleep(0.5); pathlib.Path({str(marker)!r}).write_text('survived')"
    parent_code = (
        "import subprocess, sys, time; " f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); time.sleep(10)"
    )

    with pytest.raises(ProcessTimeoutError):
        run_process([Path(sys.executable), "-c", parent_code], timeout=0.1)

    time.sleep(0.7)
    expect(not marker.exists())


def test_run_process_timeout_returns_before_detached_descendant_closes_pipes(tmp_path: Path) -> None:
    child_pid_file = tmp_path / "child-pid"
    child_code = (
        "import os, pathlib, time; "
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(os.getpid())); "
        "time.sleep(3)"
    )
    parent_code = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}], start_new_session=(os.name == 'posix')); "
        "time.sleep(30)"
    )
    started = time.monotonic()
    try:
        with pytest.raises(ProcessTimeoutError):
            run_process([Path(sys.executable), "-c", f"import os; {parent_code}"], timeout=0.2)
    finally:
        if os.name == "posix" and child_pid_file.exists():
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            with suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)

    expect(time.monotonic() - started < _DETACHED_PIPE_CLEANUP_LIMIT_SECONDS)


def test_terminate_process_tree_accepts_process_that_already_exited() -> None:
    async def start_exit_and_cleanup() -> None:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "pass",
            start_new_session=os.name == "posix",
        )
        await process.wait()
        await _terminate_process_tree(process)

    asyncio.run(start_exit_and_cleanup())
