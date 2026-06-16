"""Semantics-preserving relocation engine for basic-block reordering.

Reordering blocks in place by overwriting a block's tail, or by swapping raw
block bytes, silently corrupts control flow: relative branches keep their old
encodings while the instructions move, and any fall-through to the physically
next block is broken. The only correct way to change the physical order of
basic blocks is to relocate them as whole units and re-encode every transfer
of control for the new layout:

  * relative branches/calls are re-assembled at their new address so the
    rel8/rel32 displacement points at the (possibly moved) target;
  * a block that fell through to the next block keeps that edge — if its
    successor is no longer physically adjacent, an explicit unconditional
    jump to the successor is appended.

Because re-encoding a branch can change its size (rel8 <-> rel32) and that in
turn shifts every later block, addresses are assigned by iterating to a fixed
point. If anything cannot be proven byte-correct — a RIP-relative operand, a
branch into the middle of a block, non-contiguous blocks, a layout that no
longer fits the original byte budget, or a layout that does not converge — the
function is left untouched. Producing zero reorderings is always preferable to
emitting a corrupt one.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# A block stream item is either raw bytes copied verbatim, a control-transfer
# instruction that must be re-encoded for its new address, or an appended
# fall-through jump.
_RAW = "raw"
_BRANCH = "branch"

# Instruction types (radare2 "type" field) that transfer control via a
# relative displacement and therefore must be re-encoded when relocated.
_RELATIVE_TRANSFER_TYPES = frozenset({"jmp", "cjmp", "call"})

# Minimum number of blocks for reordering to be meaningful: the entry block is
# pinned at the function start, so at least two further blocks are needed to
# produce a different order.
_MIN_BLOCKS = 3

_MAX_LAYOUT_ITERATIONS = 12


class _BailOut(Exception):
    """Raised when a function cannot be reordered with a byte-correct result."""


def reorder_function_blocks(
    binary: Any,
    func: dict[str, Any],
    blocks: list[dict[str, Any]],
    rng: Any,
) -> int:
    """Physically reorder a function's basic blocks, preserving semantics.

    Returns the number of blocks reordered, or 0 if no reordering was applied
    (too few blocks, an unchanged order was drawn, or the function could not be
    relocated with a byte-correct result).
    """
    if len(blocks) < _MIN_BLOCKS:
        return 0

    ordered = sorted(blocks, key=lambda b: b["addr"])
    func_start = ordered[0]["addr"]
    func_end = ordered[-1]["addr"] + ordered[-1]["size"]
    budget = func_end - func_start

    try:
        plans = _build_block_plans(binary, ordered, func_start, func_end)
    except _BailOut as exc:
        logger.debug("Skipping reorder of %s: %s", func.get("name"), exc)
        return 0

    new_order = _draw_new_order(ordered, rng)
    if new_order is None:
        return 0

    try:
        layout = _lay_out(binary, new_order, plans, func_start, budget)
    except _BailOut as exc:
        logger.debug("Skipping reorder of %s: %s", func.get("name"), exc)
        return 0

    buffer = bytearray()
    for block in new_order:
        buffer += layout.block_bytes[block["addr"]]
    if len(buffer) > budget:
        return 0
    buffer += b"\x90" * (budget - len(buffer))

    if not binary.write_bytes(func_start, bytes(buffer)):
        logger.debug("Reorder of %s failed: write rejected", func.get("name"))
        return 0

    logger.info(
        "Reordered %d blocks in %s (entry pinned at 0x%x)",
        len(new_order),
        func.get("name"),
        func_start,
    )
    return len(new_order)


class _BlockPlan:
    """Relocation plan for a single basic block."""

    __slots__ = ("addr", "items", "fallthrough")

    def __init__(self, addr: int, items: list[tuple[str, Any]], fallthrough: int | None):
        self.addr = addr
        # items: list of (_RAW, bytes) | (_BRANCH, (mnemonic, target_addr))
        self.items = items
        # Original address of the block this block falls through to, or None.
        self.fallthrough = fallthrough


class _Layout:
    """Result of a converged layout pass."""

    __slots__ = ("block_bytes",)

    def __init__(self, block_bytes: dict[int, bytes]):
        self.block_bytes = block_bytes


def _build_block_plans(
    binary: Any,
    ordered: list[dict[str, Any]],
    func_start: int,
    func_end: int,
) -> dict[int, _BlockPlan]:
    """Decode every block and classify each instruction, or bail."""
    plans: dict[int, _BlockPlan] = {}
    next_addr = func_start
    for index, block in enumerate(ordered):
        addr = block["addr"]
        size = block["size"]
        if addr != next_addr:
            raise _BailOut("blocks are not contiguous")
        next_addr = addr + size

        instructions = binary.r2.cmdj(f"pdbj @ 0x{addr:x}")
        if not instructions:
            raise _BailOut(f"no instructions for block 0x{addr:x}")

        items = _classify_instructions(instructions)
        fallthrough = _fallthrough_target(instructions, ordered, index)
        plans[addr] = _BlockPlan(addr, items, fallthrough)

    return plans


def _classify_instructions(instructions: list[dict[str, Any]]) -> list[tuple[str, Any]]:
    """Turn raw instructions into copy-or-re-encode stream items, or bail."""
    items: list[tuple[str, Any]] = []
    for insn in instructions:
        disasm = insn.get("disasm", "")
        if "rip" in disasm.lower():
            raise _BailOut("RIP-relative operand cannot be relocated")

        insn_type = insn.get("type", "")
        target = insn.get("jump")
        if insn_type in _RELATIVE_TRANSFER_TYPES and isinstance(target, int):
            mnemonic = disasm.split()[0] if disasm else ""
            if not mnemonic:
                raise _BailOut("unparseable branch mnemonic")
            items.append((_BRANCH, (mnemonic, target)))
            continue

        raw = insn.get("bytes")
        if not raw:
            raise _BailOut("instruction without bytes")
        items.append((_RAW, bytes.fromhex(raw)))
    return items


def _fallthrough_target(
    instructions: list[dict[str, Any]],
    ordered: list[dict[str, Any]],
    index: int,
) -> int | None:
    """Address of the block reached by falling off this block, or None.

    A block falls through unless its last instruction is an unconditional jump
    or a return. Conditional branches expose the not-taken edge in their
    ``fail`` field; everything else continues into the next sequential block.
    """
    last = instructions[-1]
    last_type = last.get("type", "")
    if last_type == "jmp" or last_type == "ret":
        return None
    if last_type == "cjmp":
        fail = last.get("fail")
        return fail if isinstance(fail, int) else None
    if index + 1 < len(ordered):
        return int(ordered[index + 1]["addr"])
    return None


def _draw_new_order(
    ordered: list[dict[str, Any]],
    rng: Any,
) -> list[dict[str, Any]] | None:
    """Pin the entry block and shuffle the rest; None if order is unchanged."""
    tail = ordered[1:]
    shuffled = list(tail)
    rng.shuffle(shuffled)
    if shuffled == tail:
        return None
    return [ordered[0]] + shuffled


def _lay_out(
    binary: Any,
    new_order: list[dict[str, Any]],
    plans: dict[int, _BlockPlan],
    func_start: int,
    budget: int,
) -> _Layout:
    """Assign addresses and encode blocks, iterating to a fixed point."""
    addr_map = {block["addr"]: block["addr"] for block in new_order}
    order_index = {block["addr"]: i for i, block in enumerate(new_order)}

    for _ in range(_MAX_LAYOUT_ITERATIONS):
        cursor = func_start
        next_map: dict[int, int] = {}
        block_bytes: dict[int, bytes] = {}

        for position, block in enumerate(new_order):
            old_addr = block["addr"]
            next_map[old_addr] = cursor
            plan = plans[old_addr]
            successor_is_adjacent = _successor_adjacent(plan, new_order, position, order_index)
            encoded = _encode_block(binary, plan, cursor, addr_map, func_start, budget, successor_is_adjacent)
            block_bytes[old_addr] = encoded
            cursor += len(encoded)

        total = cursor - func_start
        if next_map == addr_map:
            if total > budget:
                raise _BailOut("reordered layout exceeds original byte budget")
            return _Layout(block_bytes)
        addr_map = next_map

    raise _BailOut("layout did not converge")


def _successor_adjacent(
    plan: _BlockPlan,
    new_order: list[dict[str, Any]],
    position: int,
    order_index: dict[int, int],
) -> bool:
    """True if the block's fall-through successor is the next physical block."""
    if plan.fallthrough is None:
        return True
    if position + 1 >= len(new_order):
        return False
    return bool(new_order[position + 1]["addr"] == plan.fallthrough)


def _encode_block(
    binary: Any,
    plan: _BlockPlan,
    start: int,
    addr_map: dict[int, int],
    func_start: int,
    func_end_budget: int,
    successor_is_adjacent: bool,
) -> bytes:
    """Encode one block at ``start`` using the current address estimates."""
    func_end = func_start + func_end_budget
    out = bytearray()
    cursor = start
    for kind, payload in plan.items:
        if kind == _RAW:
            out += payload
            cursor += len(payload)
            continue
        mnemonic, target = payload
        new_target = _remap_target(target, addr_map, func_start, func_end)
        encoded = _assemble_at(binary, f"{mnemonic} 0x{new_target:x}", cursor)
        out += encoded
        cursor += len(encoded)

    if plan.fallthrough is not None and not successor_is_adjacent:
        new_target = addr_map[plan.fallthrough]
        encoded = _assemble_at(binary, f"jmp 0x{new_target:x}", cursor)
        out += encoded

    return bytes(out)


def _remap_target(target: int, addr_map: dict[int, int], func_start: int, func_end: int) -> int:
    """Map an old branch target to its new address; keep external targets."""
    if target in addr_map:
        return addr_map[target]
    if target < func_start or target >= func_end:
        return target
    raise _BailOut(f"branch into middle of block at 0x{target:x}")


def _assemble_at(binary: Any, instruction: str, address: int) -> bytes:
    """Assemble ``instruction`` as if located at ``address`` (rel-correct)."""
    result = binary.r2.cmd(f"pa {instruction} @ 0x{address:x}").strip()
    if not result:
        raise _BailOut(f"failed to assemble {instruction!r}")
    try:
        return bytes.fromhex(result)
    except ValueError as exc:
        raise _BailOut(f"bad encoding for {instruction!r}: {result!r}") from exc


__all__ = ["reorder_function_blocks"]
