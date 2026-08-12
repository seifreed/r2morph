"""Real-process contract for the external process adapter."""

import sys
from pathlib import Path

from r2morph.adapters.process import run_process


def test_run_process_captures_stdout() -> None:
    result = run_process([Path(sys.executable), "-c", "print('ok')"], check=True)

    assert result.stdout_text.strip() == "ok"
