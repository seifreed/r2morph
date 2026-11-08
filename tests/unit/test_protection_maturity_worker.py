"""Process isolation checks for protection maturity measurements."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from r2morph.adapters.process import ProcessTimeoutError
from scripts.protection_maturity_worker import run_supervised_command
from tests.utils.assertions import expect


def test_supervised_command_timeout_kills_descendant_processes(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-finished"
    child_code = "import pathlib, time; time.sleep(0.5); " f"pathlib.Path({str(marker)!r}).write_text('finished')"
    parent_code = (
        "import subprocess, sys, time; " f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); time.sleep(10)"
    )

    with pytest.raises(ProcessTimeoutError):
        run_supervised_command([sys.executable, "-c", parent_code], 0.1, b"", tmp_path)
    time.sleep(0.6)

    expect(not marker.exists())
