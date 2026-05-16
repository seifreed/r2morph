"""Regression: an abandoned R2PipeAdapter must not leak radare2.

R2PipeAdapter holds a radare2 subprocess exactly like Binary, but had
no finalizer. An adapter whose owner forgot to close() leaked the
radare2 child process and its stdin/stdout pipe fds, reported as an
unraisable "Exception ignored while finalizing file <fd> mode=rb/wb"
under the mandated pytest -W error and attributed to a random later
test (flaky failures with shifting victims).

No mocks (CLAUDE.md s.4): a real R2PipeAdapter, real radare2 subprocess.
"""

from __future__ import annotations

import gc
from pathlib import Path

import pytest

from r2morph.adapters.r2pipe_adapter import R2PipeAdapter


def test_abandoned_adapter_terminates_radare2_subprocess(stable_elf_binary: Path) -> None:
    if not stable_elf_binary.exists():
        pytest.skip("stable ELF fixture not available")

    adapter = R2PipeAdapter()
    adapter.open(stable_elf_binary, flags=["-2"])

    process = adapter._r2.process  # subprocess.Popen spawned by r2pipe
    assert process.poll() is None, "radare2 subprocess should be running"

    # Abandon the adapter without close()/__exit__.
    del adapter
    gc.collect()

    assert process.poll() is not None, (
        "abandoned R2PipeAdapter leaked the radare2 subprocess " "(__del__ safety net did not quit it)"
    )
