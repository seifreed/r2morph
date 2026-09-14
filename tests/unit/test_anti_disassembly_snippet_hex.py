"""Regression: every anti-disasm snippet must have parseable bytes_hex.

The injection path in ``AntiDisassemblyPass`` calls
``bytes.fromhex(snippet.bytes_hex)`` and writes the resulting bytes at the
target address. ``bytes.fromhex`` raises ``ValueError`` for any hex string
with an odd number of characters. The pass swallows the exception in its
broad ``except`` block, logs it at debug level and returns ``False`` --
silently treating the technique as "not applied" while the user expected an
injection. Pre-fix this happened to every selection of ``TRAMPOLINE_X64``
because its ``bytes_hex`` had 37 characters (odd). The trampoline anti-disasm
technique was therefore completely inert.

No-mocks regression (CLAUDE.md sec.4): just import the snippet tables and
parse each one's hex through ``bytes.fromhex`` -- the same call the
production injection path makes.
"""

from __future__ import annotations

import pytest

from r2morph.mutations.anti_disassembly import (
    ALL_ANTI_DISASM_X64,
    SAFE_PADDING_X64,
    SEH_BASED_X86,
    TRAMPOLINE_X64,
    AntiDisassemblyPass,
)
from tests._doubles.in_memory_cave_binary import InMemoryCaveBinary
from tests.utils.assertions import expect

_EXPECTED_CODE_CAVE_ADDRESS = 0x1000


def _all_declared_snippets() -> list:
    """All snippet tables that the pass selects from at runtime."""
    return list(ALL_ANTI_DISASM_X64) + list(SAFE_PADDING_X64) + list(SEH_BASED_X86)


@pytest.mark.parametrize("snippet", _all_declared_snippets(), ids=lambda s: s.description[:60])
def test_anti_disasm_snippet_bytes_hex_is_parseable(snippet) -> None:
    """Every snippet's bytes_hex must parse via the same ``bytes.fromhex``
    call the injection path uses, and yield a non-empty byte string."""
    try:
        decoded = bytes.fromhex(snippet.bytes_hex)
    except ValueError as exc:
        raise AssertionError(
            f"snippet {snippet.description!r}: bytes_hex={snippet.bytes_hex!r} " f"is not valid hex ({exc})"
        ) from exc
    expect(decoded, f"snippet {snippet.description!r} decodes to empty bytes")


def test_trampoline_snippet_bytes_hex_specifically_parses() -> None:
    """Explicit regression on TRAMPOLINE_X64[0]: its bytes_hex was 37 chars
    long (odd) and crashed the injection path silently."""
    expect(len(TRAMPOLINE_X64) == 1)
    trampoline = TRAMPOLINE_X64[0]
    expect(
        len(trampoline.bytes_hex) % 2 == 0,
        f"TRAMPOLINE_X64 bytes_hex must be even-length (it's parsed via "
        f"bytes.fromhex); got {len(trampoline.bytes_hex)} chars: "
        f"{trampoline.bytes_hex!r}",
    )
    # And it must actually parse:
    bytes.fromhex(trampoline.bytes_hex)


def test_anti_disassembly_injects_decoy_into_code_cave() -> None:
    binary = InMemoryCaveBinary()
    pass_obj = AntiDisassemblyPass()

    result = pass_obj._inject_snippet(binary, TRAMPOLINE_X64[0])

    expect(result is not None)
    expect(binary.writes[0][0] == _EXPECTED_CODE_CAVE_ADDRESS)


def test_safe_padding_decoy_has_fall_through_encoding() -> None:
    expect(bytes.fromhex(SAFE_PADDING_X64[0].bytes_hex) == b"\xeb\x02\xe8\x00")


def test_anti_disassembly_falls_back_to_semantic_nop_padding() -> None:
    binary = InMemoryCaveBinary(cave_byte=0x90)
    pass_obj = AntiDisassemblyPass()

    result = pass_obj._inject_snippet(binary, TRAMPOLINE_X64[0])

    expect(result is not None and result[3] == SAFE_PADDING_X64[0])
