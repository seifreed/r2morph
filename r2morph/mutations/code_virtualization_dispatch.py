"""
Direct-threaded, polymorphic dispatch assembly shared by both virtualization VMs.

Threaded dispatch inlines the opcode decode at the entry and at every handler
tail instead of using one shared dispatcher block that every handler jumps back
to, so there is no central dispatcher node a devirtualizer can flag by in-degree.

To keep the inlined copies from being one repeated byte-signature, every copy
shuffles its two order-independent instruction groups:

* the opcode-decrypt XORs (each folds into ``al``; the encoder pre-mixes the
  combined key/position/checksum mask, so their order does not affect the result),
* the table-entry decrypt blocks (each folds into ``eax`` independently).

Shuffling only reorders existing instructions, so every copy is the same length:
assembled size and executed instruction count are unchanged, and the per-build
self-checksum (which scans the interpreter once) stays well within budget.

The decode head (position-mask setup + opcode load) and tail (sign-extend +
indirect jump) are identical across both VMs; the caller supplies the pieces that
differ (immediate vs frame-slot key/count/table, spacing).

The engine VM can also select an alternate ``switch`` shape per build
(:func:`switch_dispatch`): one central dispatcher block that reuses the same
decode head, opcode-decrypt XORs and bounds guard, then routes through a balanced
compare/branch (binary-search) ladder over the dense opcode indices instead of the
threaded offset-table computed goto. Varying the shape per build denies a
devirtualizer a single fixed dispatcher structure to recognize.
"""

from __future__ import annotations

import random
from collections.abc import Callable

# Handlers terminate with this back jump to the (removed) shared dispatcher; the
# threading pass splices a fresh decode copy in for each occurrence.
DISPATCH_BACK_JUMP = "  jmp vm_dispatch\n"

_DECODE_HEAD = "  mov r13, rsi\n  sub r13, r15\n  movzx eax, byte ptr [rsi]\n"
_DECODE_TAIL = "  movsxd rax, eax\n  add rax, r14\n  jmp rax\n"


def decode_block(
    *,
    opcode_xors: list[str],
    bounds: str,
    table_load: str,
    table_xors: list[str],
    rng: random.Random,
) -> str:
    """Assemble one polymorphic decode copy with its two XOR groups shuffled."""
    return (
        _DECODE_HEAD
        + "".join(rng.sample(opcode_xors, len(opcode_xors)))
        + bounds
        + table_load
        + "".join(rng.sample(table_xors, len(table_xors)))
        + _DECODE_TAIL
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


def _switch_ladder(lo: int, hi: int, path: str) -> str:
    """Emit a balanced binary-search tree over the opcode indices ``[lo, hi)``.

    ``al`` is assumed already bounds-checked into ``[lo, hi)``, so exactly one leaf
    matches. Each node tests its midpoint with ``cmp al, mid`` + ``je h_mid`` and,
    when both sub-ranges are non-empty, steers with a single ``jb`` to the left
    subtree (the right subtree falls through). Node labels encode the tree path, so
    they are unique without a running counter.
    """
    if lo >= hi:
        return ""
    mid = (lo + hi) // 2
    left = _switch_ladder(lo, mid, path + "L")
    right = _switch_ladder(mid + 1, hi, path + "R")
    node = f"  cmp al, {mid}\n  je h_{mid}\n"
    if left and right:
        left_label = f"vsw_{path}L"
        return node + f"  jb {left_label}\n" + right + f"{left_label}:\n" + left
    # At most one side remains: al is already known to be below/above ``mid`` (the
    # other range is empty), so fall straight into whichever subtree exists.
    return node + left + right


def switch_dispatch(*, opcode_xors: list[str], bounds: str, total: int, rng: random.Random) -> str:
    """Assemble the single central ``vm_dispatch`` block for the switch shape.

    Reuses the shared decode head and the same opcode-XOR decrypt group (so the
    self-checksum still folds into the opcode) and the same bounds guard as the
    threaded path, then routes through a compare/branch ladder instead of an
    offset-table computed goto. The XOR group is order-independent, so shuffling it
    keeps the decode faithful.
    """
    return (
        "vm_dispatch:\n"
        + _DECODE_HEAD
        + "".join(rng.sample(opcode_xors, len(opcode_xors)))
        + bounds
        + _switch_ladder(0, total, "")
    )
