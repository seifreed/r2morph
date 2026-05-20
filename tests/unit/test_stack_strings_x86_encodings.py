"""Regression: generate_stack_string_x86 must implement every encoding
scheme the x64 generator supports.

``generate_stack_string_x86`` handled only PLAIN, XOR_SINGLE and AES_256.
For XOR_ROLLING and ADD_SHIFT the function:

* still ran the encode step (line ``encoded_data, _ = xor_rolling(...)`` etc.),
* still emitted the ``; Stack string`` comment and the ``sub esp, N``
  stack-space prologue,
* but had NO ``elif encoding == EncodingScheme.XOR_ROLLING:`` / ``elif
  encoding == EncodingScheme.ADD_SHIFT:`` block to actually write the
  encoded bytes onto the stack and to emit a decode loop.

Net effect: the function returned an assembly stub that allocated stack
space and immediately left it uninitialised -- the "stack string" the
caller asked for did not exist on the stack at runtime. ``StackStringsPass``
silently dispatches to the x86 generator for 32-bit binaries via
``_generate_stack_string_asm``, so on x86 targets the XOR_ROLLING and
ADD_SHIFT encodings were inert.

No-mocks regression (CLAUDE.md sec.4): just compares the strings the
generators actually return.
"""

from __future__ import annotations

from r2morph.mutations.stack_strings import (
    EncodingScheme,
    generate_stack_string_x64,
    generate_stack_string_x86,
)

_DATA = b"HELLO"


def _emits_string_bytes(asm: str, count: int, address_register: str) -> bool:
    """Every encoding has to emit ``count`` byte-writes onto the stack
    (``mov byte [REG+i], 0x..``). The PLAIN/XOR_SINGLE/AES_256 branches
    already did; the XOR_ROLLING/ADD_SHIFT branches did not."""
    needle = f"mov byte [{address_register}+"
    return asm.count(needle) >= count


def test_x86_xor_rolling_emits_byte_writes_and_decode_loop() -> None:
    """Pre-fix the x86 XOR_ROLLING branch was missing entirely: the
    function returned only ``sub esp, N`` plus comments. Post-fix it
    matches the x64 layout (byte-writes + decode loop)."""
    asm, _ = generate_stack_string_x86(_DATA, encoding=EncodingScheme.XOR_ROLLING, xor_key=0x55)

    assert _emits_string_bytes(asm, count=len(_DATA), address_register="esp"), (
        "generate_stack_string_x86 must emit one mov-byte per data byte; " f"got asm:\n{asm}"
    )
    assert "decode_loop_" in asm, (
        "generate_stack_string_x86 must emit a decode loop for XOR_ROLLING; " f"got asm:\n{asm}"
    )
    # Decode loop must reference the rolling XOR's key state machine:
    assert "imul dl, 7" in asm, (
        "XOR_ROLLING decode must contain the rolling key update " f"`imul dl, 7`; got asm:\n{asm}"
    )


def test_x86_add_shift_emits_byte_writes_and_decode_loop() -> None:
    """Pre-fix the x86 ADD_SHIFT branch was missing entirely. Post-fix it
    matches the x64 layout: byte-writes followed by ``sub byte`` decode."""
    asm, _ = generate_stack_string_x86(_DATA, encoding=EncodingScheme.ADD_SHIFT, add_shift=7)

    assert _emits_string_bytes(asm, count=len(_DATA), address_register="esp"), (
        "generate_stack_string_x86 must emit one mov-byte per data byte; " f"got asm:\n{asm}"
    )
    assert "decode_loop_" in asm, "generate_stack_string_x86 must emit a decode loop for ADD_SHIFT; " f"got asm:\n{asm}"
    # Decode loop must subtract the shift back out:
    assert (
        "sub byte [edi], 7" in asm or "sub byte [edi], 0x07" in asm
    ), f"ADD_SHIFT decode must subtract the shift back; got asm:\n{asm}"


def test_x86_and_x64_emit_equivalent_byte_count_for_xor_rolling() -> None:
    """The x86 generator should emit the same number of ``mov byte`` writes
    as the x64 generator does -- one per data byte. Pre-fix x86 emitted 0
    while x64 emitted len(data)."""
    asm64, _ = generate_stack_string_x64(_DATA, encoding=EncodingScheme.XOR_ROLLING, xor_key=0x55)
    asm86, _ = generate_stack_string_x86(_DATA, encoding=EncodingScheme.XOR_ROLLING, xor_key=0x55)

    rsp_writes = asm64.count("mov byte [rsp+")
    esp_writes = asm86.count("mov byte [esp+")
    assert rsp_writes == esp_writes, (
        "x86 must emit the same number of stack byte-writes as x64; "
        f"x64={rsp_writes}, x86={esp_writes}; x86 asm:\n{asm86}"
    )
