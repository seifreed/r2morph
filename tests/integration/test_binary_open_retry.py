"""Regression test: Binary.open() retries transient r2pipe spawn races.

Bug: r2pipe spawns radare2 as a subprocess; that spawn + initial
handshake transiently fails with BrokenPipeError ("Cannot open ...")
under load, even for a valid existing file. Binary.open() had no
robustness around it, so the same single test failed intermittently
(pass/fail/fail in a fresh process each run) with shifting victims
across the suite.

These tests use a real Binary subclass as an explicit test double
(CLAUDE.md s.4: no unittest.mock / monkeypatch -- a named subclass that
overrides one seam is a real implementation, not a dynamic mock). The
double fails the spawn a fixed number of times, then delegates to the
real r2pipe spawn, so the success path exercises genuine radare2.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from r2morph.core.binary import _R2PIPE_OPEN_ATTEMPTS, Binary


class _TransientlyFailingBinary(Binary):
    """Binary whose r2 spawn fails ``fail_times`` times, then succeeds for real."""

    def __init__(self, path: str | Path, fail_times: int) -> None:
        super().__init__(path)
        self._fail_times = fail_times
        self.spawn_attempts = 0

    def _spawn_r2(self) -> Any:
        self.spawn_attempts += 1
        if self.spawn_attempts <= self._fail_times:
            raise BrokenPipeError(32, "simulated transient r2pipe spawn race")
        return super()._spawn_r2()


def test_open_recovers_from_transient_spawn_failures(stable_elf_binary: Path) -> None:
    if not stable_elf_binary.exists():
        pytest.skip("stable ELF fixture not available")

    # Fail once (simulated transient race), leaving >=2 real spawn
    # attempts in the budget so the production retry -- not test luck on
    # a single real spawn -- is what recovers.
    binary = _TransientlyFailingBinary(stable_elf_binary, fail_times=1)
    with binary as opened:
        # A later attempt used the real r2pipe spawn: info is populated.
        assert opened.r2 is not None
        assert opened.info

    # Recovered within the retry budget, after at least the injected failure.
    assert 2 <= binary.spawn_attempts <= _R2PIPE_OPEN_ATTEMPTS


def test_open_still_fails_after_exhausting_attempts(stable_elf_binary: Path) -> None:
    if not stable_elf_binary.exists():
        pytest.skip("stable ELF fixture not available")

    binary = _TransientlyFailingBinary(stable_elf_binary, fail_times=_R2PIPE_OPEN_ATTEMPTS + 5)

    # A genuinely unrecoverable spawn must still surface as an error
    # (the retry must not silently swallow real failures).
    with pytest.raises(RuntimeError, match="Failed to open binary"):
        binary.open()

    assert binary.spawn_attempts == _R2PIPE_OPEN_ATTEMPTS
