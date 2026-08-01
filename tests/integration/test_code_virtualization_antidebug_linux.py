"""
Regression: the VM's timing anti-debug fold detects a real single-stepping tracer.

The interpreter folds a timing signal into its runtime self-checksum slot: an
untraced run sees a tiny inter-read TSC delta and folds ``xor 0`` (inert, exit
code preserved), while a single-stepped run inflates the delta - each instruction
step is a kernel round-trip - past the variant's shift threshold, folds ``0xFF``
into the checksum byte, and every opcode then misdecodes into the exit path.

This exercises the real detection with a real child process under ``ptrace``
single-stepping (no mocks, no monkeypatch): a native run yields the reference exit
code, and the single-stepped run must diverge (a different code or a trap).

``ptrace(PTRACE_SINGLESTEP)`` is Linux-only, so this ``skipif``s off Linux - a
platform-capability gate, not a dodge of a real failure. On this project's macOS
dev host it will skip; a Linux CI job is the follow-up so the detection is
exercised for real and this file is not "green because skipped" forever.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass

_DATASET = Path(__file__).resolve().parents[1].parent / "dataset"
FIXTURE = _DATASET / "elf_vm_arith_x86_64"

# linux/ptrace request numbers (uapi/linux/ptrace.h); stable kernel ABI.
_PTRACE_TRACEME = 0
_PTRACE_KILL = 8
_PTRACE_SINGLESTEP = 9

# Upper bound on single steps before abandoning a runaway child: a faithful run of
# this fixture single-steps well under this, and detection trips in the prologue
# (before the main dispatch loop), so a divergent run terminates far sooner.
_STEP_CAP = 3_000_000


def _ptrace(request: int, pid: int, addr: int, data: int) -> int:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = (ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)
    return int(libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data)))


def _reap(pid: int) -> None:
    _ptrace(_PTRACE_KILL, pid, 0, 0)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _run_single_stepped(path: Path) -> int | None:
    """Exit status of ``path`` executed one instruction at a time under ptrace.

    Returns the exit code on a clean exit, ``-signal`` on a fault or termination
    (the traced program misdecoded and crashed), or ``None`` if the step cap is hit.
    """
    pid = os.fork()
    if pid == 0:  # child: request tracing, then become the target
        _ptrace(_PTRACE_TRACEME, 0, 0, 0)
        try:
            os.execv(str(path), [str(path)])
        finally:
            os._exit(127)

    os.waitpid(pid, 0)  # initial stop at execve
    for _ in range(_STEP_CAP):
        _ptrace(_PTRACE_SINGLESTEP, pid, 0, 0)
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        if os.WIFSIGNALED(status):
            return -os.WTERMSIG(status)
        stop_signal = os.WSTOPSIG(status)
        if stop_signal != signal.SIGTRAP:
            # Executing misdecoded bytes faulted (SIGSEGV/SIGILL): a trap is a
            # divergence from the clean exit code.
            _reap(pid)
            return -stop_signal
    _reap(pid)
    return None


def _virtualize(source: Path, dest: Path) -> None:
    shutil.copy(source, dest)
    dest.chmod(0o755)
    binary = Binary(str(dest), writable=True)
    binary.open()
    try:
        CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="ptrace(PTRACE_SINGLESTEP) is Linux-only; a Linux CI job exercises this (see module docstring)",
)
def test_single_stepping_tracer_diverges_from_untraced_exit(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    mutated = tmp_path / "mutated"
    _virtualize(FIXTURE, mutated)

    untraced = subprocess.run([str(mutated)], check=False).returncode
    assert untraced == 45, "benign native run must preserve the fixture's exit code"

    traced = _run_single_stepped(mutated)
    assert traced != untraced, "single-stepping did not trip the timing fold"
