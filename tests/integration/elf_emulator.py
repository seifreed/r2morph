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
_MMAP_SYSCALL = 9
_ARCH_PRCTL_SYSCALL = 158
_ARCH_SET_GS = 0x1001
_ARCH_SET_FS = 0x1002
_SYSCALL_MAP_BASE = 0x6000_0000_0000
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
_TRACE_TIME_CAP_SECONDS = 30.0
_TRACE_EMULATION_SLICE_MICROSECONDS = 1_000_000
_TRACE_EVENT_CAP = 256
_VEX128_OPCODE_EXTRACT = 0x19
_VEX128_OPCODE_INSERT = 0x18
_VEX_OPCODE_XOR = 0xEF
_VEX_MAP_0F38 = 2
_VEX128_VPMULDQ_OPCODE = 0x28
_VEX128_VPMULUDQ_OPCODE = 0x15
_VEX128_VPMULUDQ_2BYTE_OPCODE = 0xF4
_VEX128_UNPACK_ELEMENT_BITS = {
    0x60: (8, False),
    0x61: (16, False),
    0x62: (32, False),
    0x6C: (64, False),
    0x68: (8, True),
    0x69: (16, True),
    0x6A: (32, True),
    0x6D: (64, True),
}
_VEX128_SPECIAL_OPCODES = {
    0x01: (16, False, False),
    0x02: (32, False, False),
    0x03: (16, False, True),
    0x05: (16, True, False),
    0x06: (32, True, False),
    0x07: (16, True, True),
    _VEX128_VPMULUDQ_OPCODE: (32, False, False),
    0x28: (32, False, False),
}
_VEX_3_BYTE_PREFIX = 0xC4
_VEX_2_BYTE_PREFIX = 0xC5
_VEX_MAP_0F = 0x02
_VEX_MAP_0F3A = 0x03
_VEX_MODRM_REGISTER = 0xC0
_MODRM_REGISTER_MODE = 3
_SIB_INDEX_NONE = 4
_SIB_BASE_DISP32 = 5
_RIP_RELATIVE_RM = 5
_DISPLACEMENT_BYTE_SIZE = 1
_DISPLACEMENT_DWORD_SIZE = 4
_VEX128_REGISTER_INSTRUCTION_LENGTH = 4
_VEX128_THREE_BYTE_INSTRUCTION_LENGTH = 5
_VEX_XMM_LANE_BITS = 128
_VEX_XMM_LANE_MASK = (1 << _VEX_XMM_LANE_BITS) - 1


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


def _vector_register_id(prefix: str, index: int) -> int:
    return int(getattr(_x86_const, f"UC_X86_REG_{prefix}{index}"))


def _read_vector_register(mu: Any, prefix: str, index: int) -> int:
    return int(mu.reg_read(_vector_register_id(prefix, index)))


def _write_vector_register(mu: Any, prefix: str, index: int, value: int) -> None:
    mu.reg_write(_vector_register_id(prefix, index), value)


def _general_register_id(index: int) -> int:
    names = (
        "RAX",
        "RCX",
        "RDX",
        "RBX",
        "RSP",
        "RBP",
        "RSI",
        "RDI",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
    )
    return int(getattr(_x86_const, f"UC_X86_REG_{names[index]}"))


def _memory_operand(mu: Any, prefix: bytes, modrm: int, instruction: bytes) -> tuple[int, int] | None:
    mod = modrm >> 6
    if mod == _MODRM_REGISTER_MODE:
        return None
    cursor = 5 if prefix[0] == _VEX_3_BYTE_PREFIX else 4
    rm = modrm & 0x07
    index_extension = ((~prefix[1] >> 6) & 1) << 3
    base_extension = ((~prefix[1] >> 5) & 1) << 3
    if rm == _SIB_INDEX_NONE:
        sib = instruction[cursor]
        cursor += 1
        scale = 1 << (sib >> 6)
        index = (sib >> 3) & 0x07
        base = sib & 0x07
        index_value = (
            0 if index == _SIB_INDEX_NONE else int(mu.reg_read(_general_register_id(index | index_extension))) * scale
        )
        if mod == 0 and base == _SIB_BASE_DISP32:
            base_value = 0
            displacement_size = _DISPLACEMENT_DWORD_SIZE
        else:
            base_value = int(mu.reg_read(_general_register_id(base | base_extension)))
            displacement_size = _DISPLACEMENT_BYTE_SIZE if mod == 1 else _DISPLACEMENT_DWORD_SIZE
    elif mod == 0 and rm == _RIP_RELATIVE_RM:
        base_value = int(mu.reg_read(_x86_const.UC_X86_REG_RIP)) + cursor + _DISPLACEMENT_DWORD_SIZE
        index_value = 0
        displacement_size = _DISPLACEMENT_DWORD_SIZE
    else:
        base_value = int(mu.reg_read(_general_register_id(rm | base_extension)))
        index_value = 0
        displacement_size = _DISPLACEMENT_BYTE_SIZE if mod == 1 else _DISPLACEMENT_DWORD_SIZE
    displacement = int.from_bytes(instruction[cursor : cursor + displacement_size], "little", signed=True)
    return base_value + index_value + displacement, cursor + displacement_size


def _vex128_unpack_operands(
    instruction: bytes,
) -> tuple[int, int, int, int, int] | None:
    if instruction[0] == _VEX_2_BYTE_PREFIX and len(instruction) >= _VEX128_REGISTER_INSTRUCTION_LENGTH:
        prefix = instruction[:2]
        opcode_offset = 2
        modrm_offset = 3
        if prefix[1] & 0x04:
            return None
    elif instruction[0] == _VEX_3_BYTE_PREFIX and len(instruction) >= _VEX128_THREE_BYTE_INSTRUCTION_LENGTH:
        prefix = instruction[:3]
        opcode_offset = 3
        modrm_offset = 4
        if prefix[1] & 0x1F != 1 or prefix[2] & 0x04:
            return None
    else:
        return None
    opcode = instruction[opcode_offset]
    operation = _VEX128_UNPACK_ELEMENT_BITS.get(opcode)
    modrm = instruction[modrm_offset]
    if operation is None:
        return None
    destination = ((modrm >> 3) & 0x07) | (((~prefix[1] >> 7) & 1) << 3)
    source_one = (~prefix[-1] >> 3) & 0x0F
    source_two = (modrm & 0x07) | (((~prefix[1] >> 5) & 1) << 3)
    return destination, source_one, source_two, opcode, modrm_offset


def _emulate_vex128_unpack(mu: Any, instruction: bytes) -> int | None:
    operands = _vex128_unpack_operands(instruction)
    if operands is None:
        return None
    destination, source_one, source_two, opcode, modrm_offset = operands
    element_bits, high_half = _VEX128_UNPACK_ELEMENT_BITS[opcode]
    source_one_value = _read_vector_register(mu, "XMM", source_one)
    modrm = instruction[modrm_offset]
    if modrm & 0xC0 == _VEX_MODRM_REGISTER:
        source_two_value = _read_vector_register(mu, "XMM", source_two)
        length = modrm_offset + 1
    else:
        operand = _memory_operand(mu, instruction[:modrm_offset], modrm, instruction)
        if operand is None:
            return None
        address, length = operand
        source_two_value = int.from_bytes(mu.mem_read(address, 16), "little")

    elements_per_source = 128 // element_bits
    start = elements_per_source // 2 if high_half else 0
    element_mask = (1 << element_bits) - 1
    result = 0
    for output_index in range(elements_per_source):
        source = source_one_value if output_index % 2 == 0 else source_two_value
        source_index = start + output_index // 2
        result |= ((source >> (source_index * element_bits)) & element_mask) << (output_index * element_bits)
    _write_vector_register(mu, "YMM", destination, result)
    return length


def _decode_vex128_special(
    instruction: bytes,
) -> tuple[bytes, int, int, int, bool, bool] | None:
    if len(instruction) < _VEX128_REGISTER_INSTRUCTION_LENGTH:
        return None
    operation: tuple[int, bool, bool] | None
    if instruction[0] == _VEX_2_BYTE_PREFIX:
        prefix = instruction[:2]
        opcode = instruction[2]
        modrm_offset = 3
        operation = (32, False, False)
        valid = not prefix[1] & 0x04 and opcode == _VEX128_VPMULUDQ_2BYTE_OPCODE
    elif instruction[0] == _VEX_3_BYTE_PREFIX and len(instruction) >= _VEX128_THREE_BYTE_INSTRUCTION_LENGTH:
        prefix = instruction[:3]
        opcode = instruction[3]
        modrm_offset = 4
        operation = _VEX128_SPECIAL_OPCODES.get(opcode)
        valid = prefix[1] & 0x1F == _VEX_MAP_0F38 and not prefix[2] & 0x04 and operation is not None
        if operation is None:
            operation = (0, False, False)
    else:
        return None
    if not valid:
        return None
    element_bits, subtract, saturating = operation
    return prefix, opcode, modrm_offset, element_bits, subtract, saturating


def _emulate_vex128_special(mu: Any, instruction: bytes) -> int | None:
    encoding = _decode_vex128_special(instruction)
    if encoding is None:
        return None
    prefix, opcode, modrm_offset, element_bits, subtract, saturating = encoding
    modrm = instruction[modrm_offset]
    destination = ((modrm >> 3) & 0x07) | (((~prefix[1] >> 7) & 1) << 3)
    source_one = (~prefix[-1] >> 3) & 0x0F
    source_one_value = _read_vector_register(mu, "XMM", source_one)
    if modrm & 0xC0 == _VEX_MODRM_REGISTER:
        source_two = (modrm & 0x07) | (((~prefix[1] >> 5) & 1) << 3)
        source_two_value = _read_vector_register(mu, "XMM", source_two)
        length = modrm_offset + 1
    else:
        operand = _memory_operand(mu, prefix, modrm, instruction)
        if operand is None:
            return None
        address, length = operand
        source_two_value = int.from_bytes(mu.mem_read(address, 16), "little")

    if opcode in {_VEX128_VPMULDQ_OPCODE, _VEX128_VPMULUDQ_OPCODE, _VEX128_VPMULUDQ_2BYTE_OPCODE}:
        result = _vex128_multiply_result(opcode, source_one_value, source_two_value)
    else:
        result = _vex128_horizontal_result(element_bits, subtract, saturating, source_one_value, source_two_value)
    _write_vector_register(mu, "YMM", destination, result)
    return length


def _lane(value: int, index: int, bits: int) -> int:
    return (value >> (index * bits)) & ((1 << bits) - 1)


def _signed_lane(value: int, index: int, bits: int) -> int:
    lane = _lane(value, index, bits)
    sign = 1 << (bits - 1)
    return lane - (1 << bits) if lane & sign else lane


def _vex128_multiply_result(opcode: int, source_one: int, source_two: int) -> int:
    result = 0
    signed = opcode == _VEX128_VPMULDQ_OPCODE
    for output_index, source_index in enumerate((0, 2)):
        lane_reader = _signed_lane if signed else _lane
        left = lane_reader(source_one, source_index, 32)
        right = lane_reader(source_two, source_index, 32)
        result |= (left * right & ((1 << 64) - 1)) << (output_index * 64)
    return result


def _vex128_horizontal_result(
    element_bits: int,
    subtract: bool,
    saturating: bool,
    source_one: int,
    source_two: int,
) -> int:
    lane_count = 128 // element_bits
    result = 0
    for source_value, output_offset in ((source_one, 0), (source_two, lane_count // 2)):
        for pair_index in range(lane_count // 2):
            lane_reader = _signed_lane if saturating else _lane
            left = lane_reader(source_value, pair_index * 2, element_bits)
            right = lane_reader(source_value, pair_index * 2 + 1, element_bits)
            value = left - right if subtract else left + right
            if saturating:
                value = max(-(1 << (element_bits - 1)), min((1 << (element_bits - 1)) - 1, value))
            lane = output_offset + pair_index
            result |= (value & ((1 << element_bits) - 1)) << (lane * element_bits)
    return result


def _decode_three_byte_vex_registers(prefix: bytes, modrm: int) -> tuple[int, int, int]:
    vex_source = (~prefix[2] >> 3) & 0x0F
    destination = ((modrm >> 3) & 0x07) | (((~prefix[1] >> 7) & 1) << 3)
    source = (modrm & 0x07) | (((~prefix[1] >> 5) & 1) << 3)
    return destination, source, vex_source


def _emulate_vex128_extract(mu: Any, instruction: bytes) -> int | None:
    if not (
        instruction[0] == _VEX_3_BYTE_PREFIX
        and instruction[1] & 0x1F == _VEX_MAP_0F3A
        and instruction[3] == _VEX128_OPCODE_EXTRACT
        and instruction[4] & 0xC0 == _VEX_MODRM_REGISTER
    ):
        return None
    destination, source, _ = _decode_three_byte_vex_registers(instruction[:4], instruction[4])
    lane = instruction[5] & 1
    value = _read_vector_register(mu, "YMM", source) >> (lane * _VEX_XMM_LANE_BITS)
    _write_vector_register(mu, "XMM", destination, value & _VEX_XMM_LANE_MASK)
    return 6


def _emulate_vex128_insert(mu: Any, instruction: bytes) -> int | None:
    if (
        instruction[0] == _VEX_3_BYTE_PREFIX
        and instruction[1] & 0x1F == _VEX_MAP_0F3A
        and instruction[3] == _VEX128_OPCODE_INSERT
        and instruction[4] & 0xC0 == _VEX_MODRM_REGISTER
    ):
        destination, source, vex_source = _decode_three_byte_vex_registers(instruction[:4], instruction[4])
        lane = instruction[5] & 1
        inserted = _read_vector_register(mu, "XMM", source) & _VEX_XMM_LANE_MASK
        original = _read_vector_register(mu, "YMM", vex_source)
        value = (
            (original & _VEX_XMM_LANE_MASK) | (inserted << _VEX_XMM_LANE_BITS)
            if lane
            else inserted | (original & ~_VEX_XMM_LANE_MASK)
        )
        _write_vector_register(mu, "YMM", destination, value)
        return 6
    if (
        instruction[0] == _VEX_3_BYTE_PREFIX
        and instruction[1] & 0x1F == _VEX_MAP_0F3A
        and instruction[3] == _VEX128_OPCODE_INSERT
    ):
        destination, _, vex_source = _decode_three_byte_vex_registers(instruction[:4], instruction[4])
        modrm = instruction[4]
        operand = _memory_operand(mu, instruction[:4], modrm, instruction)
        if operand is None:
            return None
        address_operand, immediate_offset = operand
        lane = instruction[immediate_offset] & 1
        inserted = int.from_bytes(mu.mem_read(address_operand, 16), "little")
        original = _read_vector_register(mu, "YMM", vex_source)
        value = (
            (original & _VEX_XMM_LANE_MASK) | (inserted << _VEX_XMM_LANE_BITS)
            if lane
            else inserted | (original & ~_VEX_XMM_LANE_MASK)
        )
        _write_vector_register(mu, "YMM", destination, value)
        return immediate_offset + 1
    return None


def _emulate_vpxor(mu: Any, instruction: bytes) -> int | None:
    if (
        instruction[0] == _VEX_2_BYTE_PREFIX
        and instruction[2] == _VEX_OPCODE_XOR
        and instruction[3] & 0xC0 == _VEX_MODRM_REGISTER
    ):
        destination = (instruction[3] >> 3) & 0x07
        source = instruction[3] & 0x07
        vex_source = (~instruction[1] >> 3) & 0x0F
        value = _read_vector_register(mu, "YMM", vex_source) ^ _read_vector_register(mu, "YMM", source)
        _write_vector_register(mu, "YMM", destination, value)
        return 4
    if (
        instruction[0] == _VEX_3_BYTE_PREFIX
        and instruction[1] & 0x1F == _VEX_MAP_0F
        and instruction[3] == _VEX_OPCODE_XOR
        and instruction[4] & 0xC0 == _VEX_MODRM_REGISTER
    ):
        destination, source, vex_source = _decode_three_byte_vex_registers(instruction[:4], instruction[4])
        value = _read_vector_register(mu, "YMM", vex_source) ^ _read_vector_register(mu, "YMM", source)
        _write_vector_register(mu, "YMM", destination, value)
        return 5
    return None


def _emulate_unsupported_avx_instruction(mu: Any, address: int) -> int | None:
    """Emulate the YMM state bridges absent from the installed Unicorn build."""
    instruction = bytes(mu.mem_read(address, 15))
    length = _emulate_vex128_extract(mu, instruction)
    if length is not None:
        return length
    length = _emulate_vex128_insert(mu, instruction)
    if length is not None:
        return length
    return _emulate_vpxor(mu, instruction)


def _patch_vex128_unpack(mu: Any, address: int, state: _TraceState) -> bool:
    if state.pending_restore_end is not None and address >= state.pending_restore_end:
        if state.pending_restore_address is None or state.pending_restore_bytes is None:
            raise RuntimeError("VEX.128 restore state is incomplete")
        mu.mem_write(state.pending_restore_address, state.pending_restore_bytes)
        state.pending_restore_address = None
        state.pending_restore_end = None
        state.pending_restore_bytes = None
    if state.pending_restore_end is not None:
        return False
    instruction = bytes(mu.mem_read(address, 15))
    length = _emulate_vex128_unpack(mu, instruction)
    if length is None:
        length = _emulate_vex128_special(mu, instruction)
    if length is None:
        return False
    state.pending_restore_address = address
    state.pending_restore_end = address + length
    state.pending_restore_bytes = instruction[:length]
    mu.mem_write(address, b"\x90" * length)
    mu.ctl_remove_cache(address, address + length)
    mu.reg_write(_x86_const.UC_X86_REG_RIP, address + length)
    mu.emu_stop()
    return True


def _manual_vex128_unpack_hook(mu: Any, address: int, _size: int, user_data: Any) -> None:
    state = user_data
    state.instruction_count += 1
    if state.instruction_count >= _INSTRUCTION_CAP:
        mu.emu_stop()
        return
    _patch_vex128_unpack(mu, address, state)


def _unsupported_avx_hook(mu: Any, _user_data: Any) -> bool:
    address = int(mu.reg_read(_x86_const.UC_X86_REG_RIP))
    length = _emulate_unsupported_avx_instruction(mu, address)
    if length is None:
        return False
    mu.reg_write(_x86_const.UC_X86_REG_RIP, address + length)
    return True


def emulate_exit_code(path: Path, *, load_bias: int = 0) -> int | None:
    """Load an ELF64's PT_LOADs at ``load_bias`` and run from the entrypoint to the exit syscall."""
    raw = path.read_bytes()
    entry = struct.unpack_from("<Q", raw, 0x18)[0] + load_bias

    mu = _unicorn.Uc(_unicorn.UC_ARCH_X86, _unicorn.UC_MODE_64)
    mapped = _load_segments(mu, raw, load_bias)
    _map_pages(mu, mapped, _STACK_BASE, _STACK_SIZE)
    mu.reg_write(_x86_const.UC_X86_REG_RSP, _STACK_TOP)
    state = _TraceState()
    mu.hook_add(_unicorn.UC_HOOK_INSN_INVALID, _unsupported_avx_hook)
    mu.hook_add(_unicorn.UC_HOOK_CODE, _manual_vex128_unpack_hook, state)
    mu.hook_add(_unicorn.UC_HOOK_INSN, _syscall_hook(state, mapped), None, 1, 0, _x86_const.UC_X86_INS_SYSCALL)
    current = entry
    while "code" not in state.captured and state.instruction_count < _INSTRUCTION_CAP:
        mu.emu_start(current, 0, count=_INSTRUCTION_CAP - state.instruction_count)
        next_address = int(mu.reg_read(_x86_const.UC_X86_REG_RIP))
        if next_address == current:
            break
        current = next_address
    return state.captured.get("code")


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
            p_vaddr = struct.unpack_from("<Q", raw, offset + 16)[0]
            p_filesz = struct.unpack_from("<Q", raw, offset + 32)[0]
            p_memsz = struct.unpack_from("<Q", raw, offset + 40)[0]
            ranges.append((p_vaddr + load_bias, p_vaddr + load_bias + max(p_filesz, p_memsz)))
    return tuple(ranges)


@dataclass
class _TraceState:
    instruction_count: int = 0
    last_address: int | None = None
    fetch_fault_address: int | None = None
    indirect_jump_count: int = 0
    executable_read_count: int = 0
    indirect_jumps: list[dict[str, object]] = field(default_factory=list)
    register_samples: list[dict[str, int]] = field(default_factory=list)
    executable_reads: list[dict[str, object]] = field(default_factory=list)
    captured: dict[str, int] = field(default_factory=dict)
    pending_restore_address: int | None = None
    pending_restore_end: int | None = None
    pending_restore_bytes: bytes | None = None
    deadline: float | None = None


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
        if state.deadline is not None and state.instruction_count % 1024 == 0 and time.perf_counter() >= state.deadline:
            uc.emu_stop()
            return
        state.last_address = address
        if len(state.register_samples) < _TRACE_EVENT_CAP:
            state.register_samples.append({name: uc.reg_read(identifier) for name, identifier in register_ids.items()})
        if _patch_vex128_unpack(uc, address, state):
            return
        instruction = bytes(uc.mem_read(address, 15))
        opcode = instruction[:2]
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


def _fetch_fault_hook(state: _TraceState) -> Any:
    def on_fetch_fault(_uc: Any, _access: int, address: int, _size: int, _value: int, _user_data: object) -> bool:
        state.fetch_fault_address = address
        return False

    return on_fetch_fault


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


def _syscall_hook(state: _TraceState, mapped: set[int]) -> Any:
    next_mapping = _SYSCALL_MAP_BASE

    def on_syscall(uc: Any, _user_data: object) -> None:
        nonlocal next_mapping
        syscall = uc.reg_read(_x86_const.UC_X86_REG_RAX)
        if syscall == _EXIT_SYSCALL:
            state.captured["code"] = uc.reg_read(_x86_const.UC_X86_REG_RDI) & 0xFF
            uc.emu_stop()
        elif syscall == _MMAP_SYSCALL:
            length = uc.reg_read(_x86_const.UC_X86_REG_RSI)
            _map_pages(uc, mapped, next_mapping, length)
            uc.reg_write(_x86_const.UC_X86_REG_RAX, next_mapping)
            next_mapping += (length + _PAGE_SIZE - 1) & ~(_PAGE_SIZE - 1)
        elif syscall == _ARCH_PRCTL_SYSCALL:
            selector = uc.reg_read(_x86_const.UC_X86_REG_RDI)
            base = uc.reg_read(_x86_const.UC_X86_REG_RSI)
            if selector == _ARCH_SET_FS:
                uc.reg_write(_x86_const.UC_X86_REG_FS_BASE, base)
            elif selector == _ARCH_SET_GS:
                uc.reg_write(_x86_const.UC_X86_REG_GS_BASE, base)
            else:
                return
            uc.reg_write(_x86_const.UC_X86_REG_RAX, 0)

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
    mu.hook_add(_unicorn.UC_HOOK_INSN_INVALID, _unsupported_avx_hook)
    mu.hook_add(_unicorn.UC_HOOK_CODE, _code_hook(state, _register_ids()))
    mu.hook_add(_unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, _fetch_fault_hook(state))
    mu.hook_add(_unicorn.UC_HOOK_MEM_READ, _read_hook(state, executable_ranges))
    mu.hook_add(_unicorn.UC_HOOK_INSN, _syscall_hook(state, mapped), None, 1, 0, _x86_const.UC_X86_INS_SYSCALL)
    return _run_trace(mu, entry, state, executable_ranges)


def _run_trace(
    mu: Any, entry: int, state: _TraceState, executable_ranges: tuple[tuple[int, int], ...]
) -> dict[str, object]:
    started = time.perf_counter()
    state.deadline = started + _TRACE_TIME_CAP_SECONDS
    status = "completed"
    error: str | None = None
    try:
        mu.reg_write(_x86_const.UC_X86_REG_RIP, entry)
        while "code" not in state.captured and state.instruction_count < _INSTRUCTION_CAP:
            current = int(mu.reg_read(_x86_const.UC_X86_REG_RIP))
            mu.emu_start(
                current,
                0,
                timeout=_TRACE_EMULATION_SLICE_MICROSECONDS,
                count=_INSTRUCTION_CAP - state.instruction_count,
            )
            if state.deadline is not None and time.perf_counter() >= state.deadline:
                status = "time_cap"
                break
        if "code" not in state.captured and state.instruction_count >= _INSTRUCTION_CAP:
            status = "instruction_cap"
    except _unicorn.UcError as exc:
        status = "error"
        error = str(exc)
    result: dict[str, object] = {
        "status": status,
        "duration_seconds": time.perf_counter() - started,
        "instruction_count": state.instruction_count,
        "last_address": state.last_address,
        "fetch_fault_address": state.fetch_fault_address,
        "executable_ranges": executable_ranges,
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
