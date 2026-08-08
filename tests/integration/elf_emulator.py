"""
Shared Unicorn loader for the ELF fixtures under ``dataset/``.

Runs a produced binary for real - PT_LOADs mapped page by page, entry executed
until the exit syscall - so a test can compare the exit code of an original and
a mutated file. ``load_bias`` relocates the whole image, which is what lets an
ET_DYN fixture be run at a realistic base and expose any address baked in at
link time.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

# Imported through importorskip so a machine without Unicorn skips the importing
# test module instead of failing collection.
_unicorn = pytest.importorskip("unicorn")
_x86_const = pytest.importorskip("unicorn.x86_const")

_PT_LOAD = 1
_EXIT_SYSCALL = 0x3C
_PAGE_SIZE = 0x1000
# The stack sits below every base we load images at (0 for a linked-at-zero
# image, 0x5555_5555_4000 for a conventional PIE base), so a biased image can
# never overlap it. RSP starts mid-region so both pushes and reads stay mapped.
_STACK_BASE = 0x200000
_STACK_SIZE = 0x10000
_STACK_TOP = _STACK_BASE + _STACK_SIZE // 2
# Instruction cap to bound a runaway emulation; sized well above a faithful run.
# The interpreter's one-time entry self-checksum scans its whole body, so the
# count scales with the (now broad) handler set - a real virtualized run executes
# on the order of 10^4-10^5 instructions, so 2_000_000 leaves ample headroom
# while still terminating a true infinite loop near-instantly.
_INSTRUCTION_CAP = 2_000_000


def _map_pages(mu: Any, mapped: set[int], start: int, length: int) -> None:
    for page in range(start & ~(_PAGE_SIZE - 1), (start + length + _PAGE_SIZE - 1) & ~(_PAGE_SIZE - 1), _PAGE_SIZE):
        if page not in mapped:
            mu.mem_map(page, _PAGE_SIZE)
            mapped.add(page)


def _load_segments(mu: Any, raw: bytes, load_bias: int) -> set[int]:
    """Map every PT_LOAD at ``load_bias`` and write its file-backed bytes."""
    e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
    phentsize = struct.unpack_from("<H", raw, 0x36)[0]
    phnum = struct.unpack_from("<H", raw, 0x38)[0]

    mapped: set[int] = set()
    for i in range(phnum):
        off = e_phoff + i * phentsize
        if struct.unpack_from("<I", raw, off)[0] != _PT_LOAD:
            continue
        p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", raw, off + 8)
        _map_pages(mu, mapped, p_vaddr + load_bias, max(p_memsz, p_filesz))
        mu.mem_write(p_vaddr + load_bias, raw[p_offset : p_offset + p_filesz])
    return mapped


def emulate_exit_code(path: Path, *, load_bias: int = 0) -> int | None:
    """Load an ELF64's PT_LOADs at ``load_bias`` and run from the entrypoint to the exit syscall."""
    raw = path.read_bytes()
    entry = struct.unpack_from("<Q", raw, 0x18)[0] + load_bias

    mu = _unicorn.Uc(_unicorn.UC_ARCH_X86, _unicorn.UC_MODE_64)
    mapped = _load_segments(mu, raw, load_bias)
    _map_pages(mu, mapped, _STACK_BASE, _STACK_SIZE)
    mu.reg_write(_x86_const.UC_X86_REG_RSP, _STACK_TOP)

    captured: dict[str, int] = {}

    def on_syscall(uc: Any, _user_data: object) -> None:
        if uc.reg_read(_x86_const.UC_X86_REG_RAX) == _EXIT_SYSCALL:
            captured["code"] = uc.reg_read(_x86_const.UC_X86_REG_RDI) & 0xFF
            uc.emu_stop()

    mu.hook_add(_unicorn.UC_HOOK_INSN, on_syscall, None, 1, 0, _x86_const.UC_X86_INS_SYSCALL)
    mu.emu_start(entry, 0, count=_INSTRUCTION_CAP)
    return captured.get("code")
