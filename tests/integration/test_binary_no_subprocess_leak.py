"""Regression: a Binary must not leak the radare2 subprocess.

Bug 1: Binary had no finalizer. A Binary whose owner forgot to close()
(no context manager, an error path, an abandoned reference) leaked the
radare2 child process and its stdin/stdout pipe fds. Those pipes were
reported as an unraisable "Exception ignored while finalizing file
<fd> mode='rb'/'wb'" under the mandated pytest -W error, attributed to a
random later test (flaky failures with shifting victims).

Bug 2: open() was not idempotent. Opening an already-open Binary (a
caller that opens and then hands the Binary to a `with` block, since
__enter__ calls open() unconditionally) overwrote Binary.r2 with a fresh
session. The displaced r2pipe object is a bare object with no finalizer
of its own and is no longer reachable from Binary.__del__, so nothing
ever reaped it: one orphaned radare2 process plus two fds per re-open,
surfacing as the same shifting-victim flakiness as bug 1.

No mocks (CLAUDE.md s.4): a real Binary, real radare2 subprocess.
"""

from __future__ import annotations

import gc
import warnings
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from tests.utils.assertions import expect


def test_abandoned_binary_terminates_radare2_subprocess(stable_elf_binary: Path) -> None:
    if not stable_elf_binary.exists():
        pytest.skip("stable ELF fixture not available")

    bin_obj = Binary(stable_elf_binary)
    bin_obj.open()

    process = bin_obj.r2.process  # subprocess.Popen spawned by r2pipe
    expect(not (process.poll() is not None), "radare2 subprocess should be running")

    # Abandon the Binary without close()/__exit__.
    del bin_obj
    gc.collect()

    expect(
        process.poll() is not None,
        "abandoned Binary leaked the radare2 subprocess " "(__del__ safety net did not quit it)",
    )


def test_reopened_binary_terminates_first_radare2_subprocess(stable_elf_binary: Path) -> None:
    if not stable_elf_binary.exists():
        pytest.skip("stable ELF fixture not available")

    bin_obj = Binary(stable_elf_binary)
    bin_obj.open()
    first_process = bin_obj.r2.process  # subprocess.Popen of the first session

    try:
        bin_obj.open()  # what Binary.__enter__ does to an already-open Binary

        expect(
            first_process.poll() is not None,
            "re-opening a Binary orphaned the first radare2 subprocess "
            "(open() replaced Binary.r2 without quitting the old session)",
        )
    finally:
        bin_obj.close()


def test_reopened_binary_finalization_emits_no_resource_warning(stable_elf_binary: Path) -> None:
    if not stable_elf_binary.exists():
        pytest.skip("stable ELF fixture not available")

    bin_obj = Binary(stable_elf_binary)
    bin_obj.open()

    # The module runs under -W error, which turns the orphan's ResourceWarning
    # into an unraisable exception charged to whichever test is running when GC
    # fires. catch_warnings + simplefilter("always") observes it instead of
    # raising it, so this test owns its own failure.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        bin_obj.open()
        del bin_obj
        gc.collect()

    resource_warnings = [str(entry.message) for entry in caught if issubclass(entry.category, ResourceWarning)]
    expect(resource_warnings == [], f"re-opened Binary leaked resources at finalization: {resource_warnings}")
