"""Behavioural tests for the ptrace-tracer anti-debug fold.

The tracer probe reads ``/proc/self/status`` and folds ``0xFF`` into the runtime
checksum slot when a debugger is attached (``TracerPid != 0``) and ``0x00``
otherwise. The Unicorn harness has no kernel, so these tests emulate exactly the
three syscalls the probe issues (``openat``/``read``/``close``) with a real
in-memory fake that streams a chosen ``status`` payload back into the guest
buffer, then assert the folded checksum byte. This exercises the scan, the digit
check and the branch-free reduction end to end without a real Linux host (the real
fork/exec/ptrace divergence is covered by the Linux integration test).
"""

from __future__ import annotations

import keystone
import unicorn
from unicorn import x86_const

from r2morph.mutations.code_virtualization_antidebug import tracer_detect_asm

_SLOT = 0x88
_STACK_BASE = 0x300000
_STACK_SIZE = 0x10000
_RSP = 0x308000
_CODE_BASE = 0x400000
_SENTINEL = 0xAB  # arbitrary pre-fold checksum-slot byte

_SYS_READ = 0
_SYS_CLOSE = 3
_SYS_OPENAT = 257
_FAKE_FD = 7


def _fold_delta(status_payload: bytes | None) -> int:
    """Run the tracer probe under Unicorn with a faked ``status`` read; return the
    XOR the probe folded into the checksum slot (``0x00`` inert, ``0xFF`` detected).

    ``status_payload`` is what a ``read`` of ``/proc/self/status`` returns; ``None``
    makes ``openat`` fail (negative fd) so no bytes are ever delivered.
    """
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(tracer_detect_asm(slot=_SLOT) + "  hlt\n", addr=_CODE_BASE, as_bytes=True)

    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc.mem_map(_CODE_BASE, 0x1000)
    uc.mem_map(_STACK_BASE, _STACK_SIZE)
    uc.mem_write(_CODE_BASE, code)
    uc.reg_write(x86_const.UC_X86_REG_RSP, _RSP)
    # Seed the checksum slot so the fold is observable as an XOR delta.
    uc.mem_write(_RSP + _SLOT, bytes([_SENTINEL]))

    def on_syscall(mu: unicorn.Uc, _user: object) -> None:
        nr = mu.reg_read(x86_const.UC_X86_REG_RAX)
        if nr == _SYS_OPENAT:
            mu.reg_write(x86_const.UC_X86_REG_RAX, (-2 & 0xFFFFFFFFFFFFFFFF) if status_payload is None else _FAKE_FD)
        elif nr == _SYS_READ:
            if status_payload is None:
                mu.reg_write(x86_const.UC_X86_REG_RAX, -9 & 0xFFFFFFFFFFFFFFFF)
            else:
                buf = mu.reg_read(x86_const.UC_X86_REG_RSI)
                mu.mem_write(buf, status_payload)
                mu.reg_write(x86_const.UC_X86_REG_RAX, len(status_payload))
        elif nr == _SYS_CLOSE:
            mu.reg_write(x86_const.UC_X86_REG_RAX, 0)

    uc.hook_add(unicorn.UC_HOOK_INSN, on_syscall, None, 1, 0, x86_const.UC_X86_INS_SYSCALL)
    try:
        uc.emu_start(_CODE_BASE, _CODE_BASE + len(code))
    except unicorn.UcError:
        pass  # the trailing hlt stops emulation
    return _SENTINEL ^ uc.mem_read(_RSP + _SLOT, 1)[0]


def _status(tracer_pid: int) -> bytes:
    header = b"Name:\tvictim\nUmask:\t0022\nState:\tR (running)\nTgid:\t1234\n"
    return header + b"Pid:\t1234\nPPid:\t1000\nTracerPid:\t%d\nUid:\t0\n" % tracer_pid


def test_tracer_detect_untraced_status_folds_zero() -> None:
    assert _fold_delta(_status(0)) == 0x00


def test_tracer_detect_traced_status_folds_ff() -> None:
    assert _fold_delta(_status(1000)) == 0xFF


def test_tracer_detect_multidigit_tracer_pid_folds_ff() -> None:
    # A large tracer PID still starts with a non-'0' digit at the checked offset.
    assert _fold_delta(_status(98765)) == 0xFF


def test_tracer_detect_missing_status_folds_zero() -> None:
    # openat failing (no procfs, as under a bare Unicorn run) must stay inert.
    assert _fold_delta(None) == 0x00


def test_tracer_detect_emitted_into_the_region_interpreter() -> None:
    from r2morph.mutations.code_virtualization_antidebug import _STATUS_PATH_LO

    asm = tracer_detect_asm(slot=_SLOT)
    # The observational read (syscalls) and the branch-free fold must be present.
    assert "syscall" in asm
    assert "/proc/se" == _STATUS_PATH_LO.to_bytes(8, "little").decode()
    assert f"neg cl\n  xor byte ptr [rsp+{_SLOT}], cl" in asm
