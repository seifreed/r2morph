"""
Shared Unicorn loader for the ELF fixtures under ``fixtures/dataset/``.

Runs a produced binary for real - PT_LOADs mapped page by page, entry executed
until the exit syscall - so a test can compare the exit code of an original and
a mutated file. ``load_bias`` relocates the whole image, which is what lets an
ET_DYN fixture be run at a realistic base and expose any address baked in at
link time.
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

_EXPECTED_LEN_OPCODE_2 = 2
_EXPECTED_OPCODE_0_255 = 0xFF
_EXPECTED_OPCODE_1_0XC0_192 = 0xC0
_EXPECTED_OPCODE_1_3_7_4 = 4
_EXPECTED_REGISTER_INDEX_8 = 8


# Imported through importorskip so a machine without Unicorn skips the importing
# test module instead of failing collection.
_unicorn = pytest.importorskip("unicorn")
_x86_const = pytest.importorskip("unicorn.x86_const")

_PT_LOAD = 1
_EXIT_SYSCALL = 0x3C
_PAGE_SIZE = 0x1000
# Keep the stack in a high canonical user-space range, clear of both ordinary
# images and large appended VM segments. RSP starts mid-region so both pushes
# and reads stay mapped.
_STACK_BASE = 0x7FFF_0000_0000
_STACK_SIZE = 0x10000
_STACK_TOP = _STACK_BASE + _STACK_SIZE // 2
# Instruction cap to bound a runaway emulation; sized well above a faithful run.
# The interpreter's one-time entry self-checksum scans its whole body, so the
# count scales with the (now broad) handler set - a real virtualized run executes
# on the order of 10^4-10^5 instructions, so 2_000_000 leaves ample headroom
# while still terminating a true infinite loop near-instantly.
_INSTRUCTION_CAP = 2_000_000
_TRACE_EVENT_CAP = 256


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


def _executable_ranges(raw: bytes, load_bias: int) -> tuple[tuple[int, int], ...]:
    """Return bounded executable PT_LOAD ranges for dynamic read filtering."""
    e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
    phentsize = struct.unpack_from("<H", raw, 0x36)[0]
    phnum = struct.unpack_from("<H", raw, 0x38)[0]
    ranges: list[tuple[int, int]] = []
    for index in range(phnum):
        offset = e_phoff + index * phentsize
        p_type, p_flags = struct.unpack_from("<II", raw, offset)
        if p_type == _PT_LOAD and p_flags & 1:
            p_vaddr, p_filesz = struct.unpack_from("<QQ", raw, offset + 16)
            ranges.append((p_vaddr + load_bias, p_vaddr + load_bias + p_filesz))
    return tuple(ranges)


@dataclass
class _TraceState:
    instruction_count: int = 0
    indirect_jump_count: int = 0
    executable_read_count: int = 0
    indirect_jumps: list[dict[str, object]] = field(default_factory=list)
    register_samples: list[dict[str, int]] = field(default_factory=list)
    executable_reads: list[dict[str, object]] = field(default_factory=list)
    captured: dict[str, int] = field(default_factory=dict)


_REGISTER_NAMES = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)


def _register_ids() -> dict[str, int]:
    return {name: getattr(_x86_const, f"UC_X86_REG_{name.upper()}") for name in _REGISTER_NAMES}


def _code_hook(state: _TraceState, register_ids: dict[str, int]) -> Any:
    def on_code(uc: Any, address: int, _size: int, _user_data: object) -> None:
        state.instruction_count += 1
        if len(state.register_samples) < _TRACE_EVENT_CAP:
            state.register_samples.append({name: uc.reg_read(identifier) for name, identifier in register_ids.items()})
        opcode = bytes(uc.mem_read(address, 2))
        if (
            len(opcode) == _EXPECTED_LEN_OPCODE_2
            and opcode[0] == _EXPECTED_OPCODE_0_255
            and (opcode[1] >> 3) & 7 == _EXPECTED_OPCODE_1_3_7_4
        ):
            state.indirect_jump_count += 1
            if len(state.indirect_jumps) < _TRACE_EVENT_CAP:
                register_index = opcode[1] & 7
                jump: dict[str, object] = {"address": address, "opcode": opcode[0] << 8 | opcode[1]}
                if opcode[1] & 0xC0 == _EXPECTED_OPCODE_1_0XC0_192 and register_index < _EXPECTED_REGISTER_INDEX_8:
                    jump["target"] = uc.reg_read(register_ids[_REGISTER_NAMES[register_index]])
                    jump["vpc"] = uc.reg_read(register_ids["rsi"])
                    jump["bytecode_base"] = uc.reg_read(register_ids["r15"])
                    jump["position"] = uc.reg_read(register_ids["r13"]) & 0xFF
                state.indirect_jumps.append(jump)

    return on_code


def _read_hook(state: _TraceState, executable_ranges: tuple[tuple[int, int], ...]) -> Any:
    def on_read(uc: Any, _access: int, address: int, size: int, _value: int, _user_data: object) -> None:
        if not any(start <= address < end for start, end in executable_ranges):
            return
        state.executable_read_count += 1
        if len(state.executable_reads) < _TRACE_EVENT_CAP:
            value = bytes(uc.mem_read(address, size))
            state.executable_reads.append(
                {"address": address, "size": size, "sha256": hashlib.sha256(value).hexdigest()}
            )

    return on_read


def _syscall_hook(state: _TraceState) -> Any:
    def on_syscall(uc: Any, _user_data: object) -> None:
        if uc.reg_read(_x86_const.UC_X86_REG_RAX) == _EXIT_SYSCALL:
            state.captured["code"] = uc.reg_read(_x86_const.UC_X86_REG_RDI) & 0xFF
            uc.emu_stop()

    return on_syscall


def trace_execution(path: Path, *, load_bias: int = 0) -> dict[str, object]:
    """Capture bounded dynamic evidence for an x86-64 ELF execution."""
    raw = path.read_bytes()
    entry = struct.unpack_from("<Q", raw, 0x18)[0] + load_bias
    executable_ranges = _executable_ranges(raw, load_bias)
    state = _TraceState()
    mu = _unicorn.Uc(_unicorn.UC_ARCH_X86, _unicorn.UC_MODE_64)
    mapped = _load_segments(mu, raw, load_bias)
    _map_pages(mu, mapped, _STACK_BASE, _STACK_SIZE)
    mu.reg_write(_x86_const.UC_X86_REG_RSP, _STACK_TOP)
    mu.hook_add(_unicorn.UC_HOOK_CODE, _code_hook(state, _register_ids()))
    mu.hook_add(_unicorn.UC_HOOK_MEM_READ, _read_hook(state, executable_ranges))
    mu.hook_add(_unicorn.UC_HOOK_INSN, _syscall_hook(state), None, 1, 0, _x86_const.UC_X86_INS_SYSCALL)
    return _run_trace(mu, entry, state)


def _run_trace(mu: Any, entry: int, state: _TraceState) -> dict[str, object]:
    started = time.perf_counter()
    status = "completed"
    error: str | None = None
    try:
        mu.emu_start(entry, 0, count=_INSTRUCTION_CAP)
        if "code" not in state.captured and state.instruction_count >= _INSTRUCTION_CAP:
            status = "instruction_cap"
    except _unicorn.UcError as exc:
        status = "error"
        error = str(exc)
    result: dict[str, object] = {
        "status": status,
        "duration_seconds": time.perf_counter() - started,
        "instruction_count": state.instruction_count,
        "indirect_jump_count": state.indirect_jump_count,
        "executable_read_count": state.executable_read_count,
        "indirect_jumps": state.indirect_jumps,
        "register_samples": state.register_samples,
        "executable_reads": state.executable_reads,
    }
    if "code" in state.captured:
        result["exit_code"] = state.captured["code"]
    if error is not None:
        result["error"] = error
    return result
