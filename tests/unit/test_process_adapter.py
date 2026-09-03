"""Real-process contract for the external process adapter."""

import os
import sys
import time
from pathlib import Path

import pytest

from r2morph.adapters.process import ProcessTimeoutError, _resolve_executable, run_process
from tests.utils.assertions import expect


def test_run_process_captures_stdout() -> None:
    result = run_process([Path(sys.executable), "-c", "print('ok')"], check=True)

    expect(result.stdout_text.strip() == "ok")


def test_resolve_executable_preserves_symlink_driver_name(tmp_path: Path) -> None:
    executable_alias = tmp_path / "python-alias"
    executable_alias.symlink_to(sys.executable)

    expect(_resolve_executable(executable_alias) == str(executable_alias))


def test_run_process_executes_shebang_script_without_shell(tmp_path: Path) -> None:
    script = tmp_path / "script.sh"
    script.write_text("#!/bin/sh\nprintf 'ok'\n", encoding="utf-8")
    script.chmod(0o755)

    result = run_process([script], check=True)

    expect(result.stdout_text == "ok")


def test_run_process_timeout_terminates_child_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "child-survived"
    child_code = "import pathlib, time; " f"time.sleep(0.5); pathlib.Path({str(marker)!r}).write_text('survived')"
    parent_code = (
        "import subprocess, sys, time; " f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); time.sleep(10)"
    )

    with pytest.raises(ProcessTimeoutError):
        run_process([Path(sys.executable), "-c", parent_code], timeout=0.1)

    time.sleep(0.7)
    expect(marker.exists() is (os.name != "posix"))
