"""Regression: an abandoned Binary must not leak the radare2 subprocess.

Bug: Binary had no finalizer. A Binary whose owner forgot to close()
(no context manager, an error path, an abandoned reference) leaked the
radare2 child process and its stdin/stdout pipe fds. Those pipes were
reported as an unraisable "Exception ignored while finalizing file
<fd> mode='rb'/'wb'" under the mandated pytest -W error, attributed to a
random later test (flaky failures with shifting victims).

No mocks (CLAUDE.md s.4): a real Binary, real radare2 subprocess.
"""

from __future__ import annotations

import gc
from pathlib import Path

import pytest

from r2morph.core.binary import Binary


def test_abandoned_binary_terminates_radare2_subprocess(stable_elf_binary: Path) -> None:
    if not stable_elf_binary.exists():
        pytest.skip("stable ELF fixture not available")

    bin_obj = Binary(stable_elf_binary)
    bin_obj.open()

    process = bin_obj.r2.process  # subprocess.Popen spawned by r2pipe
    assert process.poll() is None, "radare2 subprocess should be running"

    # Abandon the Binary without close()/__exit__.
    del bin_obj
    gc.collect()

    assert process.poll() is not None, (
        "abandoned Binary leaked the radare2 subprocess " "(__del__ safety net did not quit it)"
    )
