"""
Direct-threaded, polymorphic dispatch assembly shared by both virtualization VMs.

Threaded dispatch inlines the opcode decode at the entry and at every handler
tail instead of using one shared dispatcher block that every handler jumps back
to, so there is no central dispatcher node a devirtualizer can flag by in-degree.

To keep the inlined copies from being one repeated byte-signature, every copy
shuffles its two order-independent instruction groups:

* the opcode-decrypt XORs (each folds into ``al``; the encoder pre-mixes the
  combined key/stream/checksum mask, so their order does not affect the result),
* the table-entry decrypt blocks (each folds into ``eax`` independently).

Shuffling reorders existing instruction groups, while the transfer tail may use
either equivalent form; the per-build self-checksum still scans the assembled
interpreter once and stays well within budget.

The decode head (position-mask setup + opcode load) is identical across both VMs;
the caller supplies the pieces that differ (immediate vs frame-slot key/count/table,
spacing). The indirect transfer uses either ``jmp rax`` or ``push rax; ret`` per
generated copy; the latter consumes its own pushed return address and preserves the
handler's stack contract while removing one fixed tail signature.

The VMs emit two dispatch personalities: the inline threaded form described above
and a central decoder using the same encrypted relative-offset table. The central
form is deliberately not a compare/branch ladder: a decompiler can rebuild such
a ladder into a plain ``switch`` and recover the opcode mapping, while both forms
here retain the runtime-encrypted table.
"""

from __future__ import annotations

from collections.abc import Callable

import r2morph.core.randomness as random

# Handlers terminate with this back jump to the (removed) shared dispatcher; the
# threading pass splices a fresh decode copy in for each occurrence.
DISPATCH_BACK_JUMP = "  jmp vm_dispatch\n"

_STREAM_MULTIPLIER = 181
_STREAM_INCREMENT = 109
_DECODE_HEAD = (
    "  mov r13, rsi\n"
    "  sub r13, r15\n"
    f"  imul r13d, r13d, {_STREAM_MULTIPLIER}\n"
    f"  add r13b, {_STREAM_INCREMENT}\n"
    "  movzx eax, byte ptr [rsi]\n"
)
_DECODE_TAIL = "  movsxd rax, eax\n  add rax, r14\n  jmp rax\n"
_STACK_TRANSFER_TAIL = "  movsxd rax, eax\n  add rax, r14\n  push rax\n  ret\n"


def bytecode_position_mask(position: int) -> int:
    """Map a bytecode offset to the progressive mask used by the dispatcher."""
    return (position * _STREAM_MULTIPLIER + _STREAM_INCREMENT) & 0xFF


def _indirect_transfer_tail(rng: random.Random) -> str:
    """Choose an equivalent indirect transfer for one generated dispatch copy."""
    return _STACK_TRANSFER_TAIL if rng.getrandbits(1) else _DECODE_TAIL


def offset_jump_block(
    *,
    index_setup: str,
    bounds: str,
    table_load: str,
    table_xors: list[str],
    rng: random.Random,
) -> str:
    """Jump through one runtime-encrypted relative-offset table."""
    return (
        index_setup
        + bounds
        + table_load
        + "".join(rng.sample(table_xors, len(table_xors)))
        + _indirect_transfer_tail(rng)
    )


def decode_block(
    *,
    opcode_xors: list[str],
    bounds: str,
    table_load: str,
    table_xors: list[str],
    rng: random.Random,
) -> str:
    """Assemble one polymorphic decode copy with its two XOR groups shuffled."""
    return offset_jump_block(
        index_setup=_DECODE_HEAD + "".join(rng.sample(opcode_xors, len(opcode_xors))),
        bounds=bounds,
        table_load=table_load,
        table_xors=table_xors,
        rng=rng,
    )


def thread_back_jumps(interpreter: str, make_decode: Callable[[], str]) -> str:
    """Replace every handler-tail back jump with a freshly built decode copy.

    Each gap gets its own ``make_decode()`` call, so no two inlined decodes in one
    interpreter share a byte layout (beyond the unavoidable head/tail).
    """
    parts = interpreter.split(DISPATCH_BACK_JUMP)
    out = [parts[0]]
    for part in parts[1:]:
        out.append(make_decode())
        out.append(part)
    return "".join(out)
