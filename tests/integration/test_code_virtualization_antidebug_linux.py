"""
Regression: the VM's anti-debug fold detects a real tracer on real Linux.

The interpreter reads ``/proc/self/status`` and folds its ``TracerPid`` signal into
the runtime self-checksum slot: ``xor 0`` on a benign run and ``0xFF`` under a
debugger, making every opcode misdecode into the exit path.

Both are exercised with a real child process under ``ptrace`` (no mocks, no
monkeypatch): a native run yields the reference exit code, and the traced run must
diverge (a different code or a trap).

``ptrace`` is Linux-only, so these ``skipif`` off Linux - a platform-capability
gate, not a dodge of a real failure. On this project's macOS dev host they skip; a
Linux CI job is the follow-up so the detection is exercised for real and this file
is not "green because skipped" forever.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import shutil
import signal
import sys
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect
from tests.utils.process import run_command

_EXPECTED_UNTRACED_45 = 45
_EXPECTED_UNTRACED_45_2 = 45


_DATASET = Path(__file__).resolve().parents[1].parent / "fixtures" / "dataset"
FIXTURE = _DATASET / "elf_vm_arith_x86_64"

# linux/ptrace request numbers (uapi/linux/ptrace.h); stable kernel ABI.
_PTRACE_TRACEME = 0
_PTRACE_CONT = 7
_PTRACE_KILL = 8
_PTRACE_SINGLESTEP = 9

# Fatal signals a misdecoded interpreter raises when it runs corrupt bytecode.
_FATAL_SIGNALS = (signal.SIGSEGV, signal.SIGILL, signal.SIGBUS, signal.SIGABRT)

# Upper bound on single steps before abandoning a runaway child. The tracer probe
# completes in the prologue, well before this budget; checksum corruption may loop.
_STEP_CAP = 100_000


def _ptrace(request: int, pid: int, addr: int, data: int) -> int:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = (ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)
    return int(libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data)))


def _exec_target(path: Path) -> None:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.execv.argtypes = (ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p))
    libc.execv.restype = ctypes.c_int
    encoded_path = os.fsencode(path)
    arguments = (ctypes.c_char_p * 2)(encoded_path, None)
    libc.execv(encoded_path, arguments)
    os._exit(127)


def _reap(pid: int) -> None:
    _ptrace(_PTRACE_KILL, pid, 0, 0)
    with contextlib.suppress(ChildProcessError):
        os.waitpid(pid, 0)


def _run_single_stepped(path: Path) -> int | None:
    """Exit status of ``path`` executed one instruction at a time under ptrace.

    Returns the exit code on a clean exit, ``-signal`` on a fault or termination
    (the traced program misdecoded and crashed), or ``None`` if the step cap is hit.
    """
    pid = os.fork()
    if pid == 0:  # child: request tracing, then become the target
        _ptrace(_PTRACE_TRACEME, 0, 0, 0)
        try:
            _exec_target(path)
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


def _run_attached(path: Path) -> int | None:
    """Exit status of ``path`` run under an *attached but free-running* tracer.

    The child requests tracing then ``execv``s the target; the parent lets it run
    at full speed with ``PTRACE_CONT``. The ``/proc/self/status`` ``TracerPid`` fold
    trips without relying on instruction timing. Returns
    the exit code on a clean exit, ``-signal`` on a fault, or ``None`` if it neither
    exits nor faults within a small budget of continuations.
    """
    pid = os.fork()
    if pid == 0:  # child: request tracing, then become the target
        _ptrace(_PTRACE_TRACEME, 0, 0, 0)
        try:
            _exec_target(path)
        finally:
            os._exit(127)

    os.waitpid(pid, 0)  # initial stop at execve
    for _ in range(64):
        _ptrace(_PTRACE_CONT, pid, 0, 0)
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        if os.WIFSIGNALED(status):
            return -os.WTERMSIG(status)
        stop_signal = os.WSTOPSIG(status)
        if stop_signal in _FATAL_SIGNALS:
            # Executing misdecoded bytes faulted: a divergence from the clean exit.
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


@pytest.mark.slow
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="ptrace(PTRACE_SINGLESTEP) is Linux-only; a Linux CI job exercises this (see module docstring)",
)
def test_single_stepping_tracer_diverges_from_untraced_exit(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    mutated = tmp_path / "mutated"
    _virtualize(FIXTURE, mutated)

    untraced = run_command([str(mutated)], check=False).returncode
    expect(untraced == _EXPECTED_UNTRACED_45, "benign native run must preserve the fixture's exit code")

    traced = _run_single_stepped(mutated)
    expect(traced != untraced, "single-stepping did not trip the TracerPid fold")


@pytest.mark.slow
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="ptrace is Linux-only; a Linux CI job exercises this (see module docstring)",
)
def test_attached_tracer_diverges_from_untraced_exit(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"fixture missing: {FIXTURE}")

    mutated = tmp_path / "mutated"
    _virtualize(FIXTURE, mutated)

    untraced = run_command([str(mutated)], check=False).returncode
    expect(untraced == _EXPECTED_UNTRACED_45_2, "benign native run must preserve the fixture's exit code")

    # Free-running tracing still appears in /proc through TracerPid.
    traced = _run_attached(mutated)
    expect(traced != untraced, "an attached tracer did not trip the /proc TracerPid fold")
