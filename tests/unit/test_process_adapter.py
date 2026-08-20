"""Real-process contract for the external process adapter."""

import sys
from pathlib import Path

from r2morph.adapters.process import _resolve_executable, run_process
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
