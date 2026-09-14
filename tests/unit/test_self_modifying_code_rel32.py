"""
Regression test: SelfModifyingCode must range-check its rel32 jumps.

``_build_xor_decrypt_stub`` ended the stub with ``b"\\xe9" +
struct.pack("<i", rel_offset)`` (an x86 ``jmp rel32``) without checking
that ``rel_offset`` fits in a signed 32-bit integer. ``apply`` first
builds a *provisional* stub with ``cave_addr=0`` purely to measure its
size, which makes ``rel_offset == func_addr - (stub_len + 5)``. On any
binary whose functions load above ~2 GiB (every macOS x86_64 Mach-O,
PIE ELFs, the 145-function /bin/ls used in the dynamic smoke) that
exceeds int32 and ``struct.pack`` raised
``struct.error: 'i' format requires -2147483648 <= number <=
2147483647``. The failure was contained by the pipeline's per-pass
isolation boundary, so the pass was silently non-functional on real
binaries while the test suite (tiny low-address fixtures) stayed green.

This calls the real ``_build_xor_decrypt_stub`` with real integer
arguments (no mocks, no monkeypatch). It is a pure function of its
arguments, so no binary is needed to reproduce the bug deterministically.
"""

import struct

from r2morph.mutations.self_modifying_code import SelfModifyingCodePass
from tests.utils.assertions import expect

_EXPECTED_STUB_5_233 = 0xE9


_PROLOGUE = b"\x90\x90\x90\x90\x90"


class _DisassemblyBinary:
    def __init__(self, disassembly: list[dict[str, object]]) -> None:
        self.disassembly = disassembly

    def get_function_disasm(self, _address: int) -> list[dict[str, object]]:
        return self.disassembly


_INT32_MAX = 2147483647


def test_build_xor_decrypt_stub_far_target_returns_none() -> None:
    # func_addr far above 2**31 (typical macOS x86_64 load address);
    # with cave_addr=0 the stub's final jmp rel32 cannot be encoded.
    result = SelfModifyingCodePass()._build_xor_decrypt_stub(
        cave_addr=0,
        func_addr=0x140000000,
        func_size=64,
        key_byte=0xAB,
        saved_prologue=_PROLOGUE,
    )
    expect(not (result is not None))


def test_build_xor_decrypt_stub_near_target_builds_valid_jmp() -> None:
    func_addr = 0x140000000
    cave_addr = func_addr + 0x200  # in-range, realistic nearby cave
    stub = SelfModifyingCodePass()._build_xor_decrypt_stub(
        cave_addr=cave_addr,
        func_addr=func_addr,
        func_size=64,
        key_byte=0xAB,
        saved_prologue=_PROLOGUE,
    )
    expect(stub is not None)
    expect(stub[-5] == _EXPECTED_STUB_5_233)
    rel = struct.unpack("<i", stub[-4:])[0]
    expect(-_INT32_MAX - 1 <= rel <= _INT32_MAX)
    # rel32 is relative to the address after the 5-byte jmp.
    expect(rel == func_addr - (cave_addr + len(stub)))


def test_build_xor_decrypt_stub_preserves_sysv_entry_registers() -> None:
    stub = SelfModifyingCodePass()._build_xor_decrypt_stub(
        cave_addr=0x1200,
        func_addr=0x1000,
        func_size=64,
        key_byte=0xAB,
        saved_prologue=_PROLOGUE,
    )

    expect(stub is not None)
    expect(stub[:9] == b"\x50\x51\x52\x57\x56\x41\x50\x41\x51")
    expect(b"\x41\x5b\x41\x5a\x41\x59\x41\x58\x5e\x5f\x5a\x59\x58" in stub)


def test_straight_line_body_rejects_calls_and_rip_relative_access() -> None:
    pass_obj = SelfModifyingCodePass()

    call_body = _DisassemblyBinary([{"disasm": "call 0x2000"}])
    rip_body = _DisassemblyBinary([{"disasm": "mov rax, [rip + 0x10]"}])

    expect(not pass_obj._has_straight_line_body(call_body, 0x1000))
    expect(not pass_obj._has_straight_line_body(rip_body, 0x1000))
