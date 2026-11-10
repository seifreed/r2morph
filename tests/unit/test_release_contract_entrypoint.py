"""Regression tests for the release-contract command entry point."""

from __future__ import annotations

import sys
from pathlib import Path

from tests.utils.assertions import expect
from tests.utils.process import run_command

_ROOT = Path(__file__).resolve().parents[2]


def test_release_contract_script_entrypoint_loads_repository_root() -> None:
    result = run_command(
        [sys.executable, str(_ROOT / "scripts" / "check_release_contract.py")],
        cwd=_ROOT,
        text=True,
        timeout=30,
    )

    expect(result.returncode == 0 and "release contract valid:" in result.stdout, result.stderr)
