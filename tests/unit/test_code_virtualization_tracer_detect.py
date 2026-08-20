"""Behavioural tests for the ptrace-tracer anti-debug fold.

The tracer probe reads ``/proc/self/status`` and folds ``0xFF`` into the runtime
checksum slot when a debugger is attached (``TracerPid != 0``) and ``0x00``
otherwise. The path words and scan tag are not plaintext immediates: they live in
an appended island as ``const ^ broadcast(checksum)`` and are reconstructed at
runtime by XORing the checksum broadcast back out. The Unicorn harness has no
kernel, so these tests assemble the probe together with its island, patch the
island against the seeded checksum-slot byte exactly as the blob builder does,
emulate the three syscalls the probe issues (``openat``/``read``/``close``) with a
real in-memory fake that streams a chosen ``status`` payload, then assert the
folded checksum byte. This exercises the checksum-keyed reconstruction, the scan,
the digit check and the branch-free reduction end to end without a real Linux host
(the real fork/exec/ptrace divergence is covered by the Linux integration test).
"""

from __future__ import annotations

from contextlib import suppress

import keystone
import unicorn
from unicorn import x86_const

from r2morph.mutations.code_virtualization_antidebug import (
    _STATUS_PATH_LO,
    _TRACER_ISLAND_LEN,
    _TRACERPID_TAG,
    patch_tracer_constants,
    tracer_const_island_asm,
    tracer_detect_asm,
)
from tests.utils.assertions import expect

_EXPECTED_FOLD_DELTA_STATUS_1000_255 = 0xFF
_EXPECTED_FOLD_DELTA_STATUS_98765_255 = 0xFF


_SLOT = 0x88
_STACK_BASE = 0x300000
_STACK_SIZE = 0x10000
_RSP = 0x308000
_CODE_BASE = 0x400000
_SENTINEL = 0xAB  # the pre-fold checksum-slot byte; doubles as the de-mask key

_SYS_READ = 0
_SYS_CLOSE = 3
_SYS_OPENAT = 257
_FAKE_FD = 7


def _fold_delta(status_payload: bytes | None) -> int:
    """Run the tracer probe under Unicorn with a faked ``status`` read; return the
    XOR the probe folded into the checksum slot (``0x00`` inert, ``0xFF`` detected).

    ``status_payload`` is what a ``read`` of ``/proc/self/status`` returns; ``None``
    makes ``openat`` fail (negative fd) so no bytes are ever delivered. The island is
    patched against ``_SENTINEL`` (the seeded checksum byte), so a correct scan tag
    only reconstructs if the checksum-keyed de-mask works.
    """
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    asm = tracer_detect_asm(slot=_SLOT) + "  hlt\n" + tracer_const_island_asm()
    code = bytearray(ks.asm(asm, addr=_CODE_BASE, as_bytes=True)[0])
    # The island is the assembly's tail; patch it against the seeded checksum byte
    # exactly as build_region_blob does once the build checksum is known.
    patch_tracer_constants(code, len(code) - _TRACER_ISLAND_LEN, _SENTINEL)

    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    uc.mem_map(_CODE_BASE, 0x1000)
    uc.mem_map(_STACK_BASE, _STACK_SIZE)
    uc.mem_write(_CODE_BASE, bytes(code))
    uc.reg_write(x86_const.UC_X86_REG_RSP, _RSP)
    # Seed the checksum slot so the fold is observable as an XOR delta and the
    # de-mask reconstructs the real constants.
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
    with suppress(unicorn.UcError):
        uc.emu_start(_CODE_BASE, _CODE_BASE + len(code))
    return _SENTINEL ^ uc.mem_read(_RSP + _SLOT, 1)[0]


def _status(tracer_pid: int) -> bytes:
    header = b"Name:\tvictim\nUmask:\t0022\nState:\tR (running)\nTgid:\t1234\n"
    return header + b"Pid:\t1234\nPPid:\t1000\nTracerPid:\t%d\nUid:\t0\n" % tracer_pid


def test_tracer_detect_untraced_status_folds_zero() -> None:
    expect(_fold_delta(_status(0)) == 0)


def test_tracer_detect_traced_status_folds_ff() -> None:
    expect(_fold_delta(_status(1000)) == _EXPECTED_FOLD_DELTA_STATUS_1000_255)


def test_tracer_detect_multidigit_tracer_pid_folds_ff() -> None:
    # A large tracer PID still starts with a non-'0' digit at the checked offset.
    expect(_fold_delta(_status(98765)) == _EXPECTED_FOLD_DELTA_STATUS_98765_255)


def test_tracer_detect_missing_status_folds_zero() -> None:
    # openat failing (no procfs, as under a bare Unicorn run) must stay inert.
    expect(_fold_delta(None) == 0)


def test_tracer_detect_emitted_into_the_region_interpreter() -> None:
    asm = tracer_detect_asm(slot=_SLOT)
    # The observational read (syscalls) and the branch-free fold must be present.
    expect(not ("syscall" not in asm))
    expect(_STATUS_PATH_LO.to_bytes(8, "little").decode() == "/proc/se")
    expect(not (f"neg cl\n  xor byte ptr [rsp+{_SLOT}], cl" not in asm))


def test_tracer_detect_emits_no_plaintext_constant_immediate() -> None:
    # Neither the "/proc/se" path word nor the "TracerPi" scan tag may appear as a
    # plaintext immediate: both are loaded from the checksum-keyed island instead.
    asm = tracer_detect_asm(slot=_SLOT)
    expect(hex(_STATUS_PATH_LO) not in asm)
    expect(hex(_TRACERPID_TAG) not in asm)


def test_tracer_detect_syscall_numbers_are_not_plaintext_immediates() -> None:
    # The openat/close syscall numbers must not appear as plaintext immediates: a
    # ``mov rax, 257`` lets a decompiler attribute the probe as sys_openat/read/close.
    # They are de-masked from the checksum-keyed island instead, so the number in the
    # syscall register is opaque and the syscalls stay unnamed in the pseudocode.
    asm = tracer_detect_asm(slot=_SLOT)
    expect(str(_SYS_OPENAT) not in asm)
    expect("mov eax, 3" not in asm and "mov rax, 3" not in asm)
    # The AT_FDCWD dirfd (-100) is an openat tell on its own; it is masked too.
    expect("-100" not in asm)


def test_tracer_detect_tracerpid_zero_compare_is_not_a_plaintext_immediate() -> None:
    # The '0' the tracer digit is compared against must not appear as ``cmp al, 0x30``:
    # a decompiler folds that to ``!= '0'`` and names the TracerPid check. It is
    # de-masked from the checksum-keyed island and compared register-to-register.
    asm = tracer_detect_asm(slot=_SLOT)
    expect("0x30" not in asm)
    expect(not ("cmp al, dil" not in asm))


def test_tracer_island_masks_constants_by_checksum() -> None:
    # The stored island bytes vary with the build checksum and never carry the
    # plaintext constants: two checksums produce different ciphertext, and the
    # "/proc/se" plaintext word is absent from a patched island.
    island_a = bytearray(_TRACER_ISLAND_LEN)
    island_b = bytearray(_TRACER_ISLAND_LEN)
    patch_tracer_constants(island_a, 0, 0x11)
    patch_tracer_constants(island_b, 0, 0x22)
    expect(island_a != island_b)
    expect(_STATUS_PATH_LO.to_bytes(8, "little") not in bytes(island_a))
