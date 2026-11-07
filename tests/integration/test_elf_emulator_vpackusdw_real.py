"""Real ELF coverage for the emulator's AVX2 packing fallback."""

from __future__ import annotations

import pytest

from tests.integration.elf_emulator import _emulate_unsupported_avx_instruction, _unicorn, _x86_const
from tests.utils.assertions import expect

pytestmark = pytest.mark.integration

_CODE_ADDRESS = 0x1000
_DATA_ADDRESS = 0x2000
_INSTRUCTION_LENGTH = 9
_SOURCE_VALUES = (1, 2, 3, 4, -1, 65535, 65536, 70000)
_MEMORY_VALUES = (5, 6, 7, 8, 9, 10, 11, 12)
_EXPECTED_VALUES = (1, 2, 3, 4, 5, 6, 7, 8, 0, 65535, 65535, 65535, 9, 10, 11, 12)


def test_vpackusdw_memory_operand_emulation_preserves_saturation_and_lanes() -> None:
    emulator = _unicorn.Uc(_unicorn.UC_ARCH_X86, _unicorn.UC_MODE_64)
    emulator.mem_map(_CODE_ADDRESS, 0x1000)
    emulator.mem_map(_DATA_ADDRESS, 0x1000)
    emulator.mem_write(_DATA_ADDRESS, b"".join(value.to_bytes(4, "little", signed=True) for value in _MEMORY_VALUES))
    emulator.reg_write(_x86_const.UC_X86_REG_RIP, _CODE_ADDRESS)
    emulator.reg_write(
        _x86_const.UC_X86_REG_YMM0,
        int.from_bytes(b"".join(value.to_bytes(4, "little", signed=True) for value in _SOURCE_VALUES), "little"),
    )
    displacement = _DATA_ADDRESS - (_CODE_ADDRESS + _INSTRUCTION_LENGTH)
    instruction = b"\xc4\xe2\x7d\x2b\x15" + displacement.to_bytes(4, "little", signed=True)
    emulator.mem_write(_CODE_ADDRESS, instruction)

    instruction_length = _emulate_unsupported_avx_instruction(emulator, _CODE_ADDRESS)
    result = emulator.reg_read(_x86_const.UC_X86_REG_YMM2).to_bytes(32, "little")
    expected = b"".join(value.to_bytes(2, "little") for value in _EXPECTED_VALUES)

    expect(
        instruction_length == _INSTRUCTION_LENGTH and result == expected,
        f"VPACKUSDW emulator mismatch: {instruction_length=}, {result.hex()=}, {expected.hex()=}",
    )
