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

_PROLOGUE = b"\x90\x90\x90\x90\x90"
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
    assert result is None


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
    assert stub is not None
    assert stub[-5] == 0xE9  # jmp rel32 opcode
    rel = struct.unpack("<i", stub[-4:])[0]
    assert -_INT32_MAX - 1 <= rel <= _INT32_MAX
    # rel32 is relative to the address after the 5-byte jmp.
    assert rel == func_addr - (cave_addr + len(stub))
