"""
Whole-function control-flow virtualization (lifting side).

Where :mod:`code_virtualization_engine` virtualizes a single straight-line
register run, this module lifts an entire function whose every instruction is a
register op, a comparison, or a branch into a :class:`Region`. The control flow
is lowered into VM items: comparisons capture the real RFLAGS into a private
slot, conditional/unconditional branches retarget the bytecode pointer, and
each terminator (``ret``/``syscall``) becomes a distinct VM exit back to native
code (any number of terminators is supported).

A function that is not fully reducible to this model (a call, a memory operand,
an indirect or out-of-function branch, no terminator) yields ``None`` and is
left untouched.

The interpreter assembly and bytecode generation for a lowered region live in
:mod:`code_virtualization_region_codegen`; the shared value objects in
:mod:`code_virtualization_region_models`.
"""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.mutations.code_virtualization_engine import (
    GP_REGISTERS,
    RSP_INDEX,
    VirtualizedOp,
    decode_instruction,
)
from r2morph.mutations.code_virtualization_region_decoders import (
    _decode_cmp_mem,
    _decode_imul,
    _decode_imul3,
    _decode_incdec,
    _decode_lea,
    _decode_lea_indexed,
    _decode_leave,
    _decode_memory_mov,
    _decode_mov_from_rsp,
    _decode_mov_to_rsp,
    _decode_movx,
    _decode_op_mem,
    _decode_op_mem_indexed,
    _decode_op_memdst,
    _decode_pop,
    _decode_push,
    _decode_riprel_mov,
    _decode_rsp_arith,
    _decode_shift,
    _decode_two_operand,
)
from r2morph.mutations.code_virtualization_region_models import (
    Region,
    RegionScheme,
    _op_key,
)

logger = logging.getLogger(__name__)

# r2 branch mnemonic -> the native conditional jump the interpreter emits.
_CONDITION: dict[str, str] = {
    "je": "je",
    "jz": "je",
    "jne": "jne",
    "jnz": "jne",
    "jl": "jl",
    "jnge": "jl",
    "jge": "jge",
    "jnl": "jge",
    "jg": "jg",
    "jnle": "jg",
    "jle": "jle",
    "jng": "jle",
    "jb": "jb",
    "jc": "jb",
    "jnae": "jb",
    "jae": "jae",
    "jnc": "jae",
    "jnb": "jae",
    "jbe": "jbe",
    "jna": "jbe",
    "ja": "ja",
    "jnbe": "ja",
    "js": "js",
    "jns": "jns",
    "jo": "jo",
    "jno": "jno",
    "jp": "jp",
    "jpe": "jp",
    "jnp": "jnp",
    "jpo": "jnp",
}


def _classify(insn: dict[str, Any]) -> list[Any] | None:
    """Build the VM item for one body instruction, or ``None`` if unsupported."""
    kind = insn.get("type", "")
    text = insn.get("opcode", "")
    if kind == "nop":
        return ["nop"]
    if kind in ("mov", "add", "sub", "xor", "and", "or"):
        op = decode_instruction(text)
        if op is not None:
            return ["op", op]
        if kind in ("add", "sub"):
            rsp_arith = _decode_rsp_arith(text)
            if rsp_arith is not None:
                return [*rsp_arith]
        if kind == "mov":
            from_rsp = _decode_mov_from_rsp(text)
            if from_rsp is not None:
                return [*from_rsp]
            to_rsp = _decode_mov_to_rsp(text)
            if to_rsp is not None:
                return [*to_rsp]
            memory = _decode_memory_mov(text)
            if memory is not None:
                return [*memory]
            riprel = _decode_riprel_mov(text, insn.get("addr", 0), insn.get("size", 0))
            if riprel is not None:
                return [*riprel]
            movx = _decode_movx(text)
            return [*movx] if movx is not None else None
        incdec = _decode_incdec(text)
        if incdec is not None:
            return [*incdec]
        op_mem = _decode_op_mem(text, kind, insn.get("addr", 0), insn.get("size", 0))
        if op_mem is not None:
            return [*op_mem]
        op_memdst = _decode_op_memdst(text, kind, insn.get("addr", 0), insn.get("size", 0))
        if op_memdst is not None:
            return [*op_memdst]
        op_mem_idx = _decode_op_mem_indexed(text, kind)
        return [*op_mem_idx] if op_mem_idx is not None else None
    if kind == "cmp":
        compare = _decode_two_operand(text, "cmp")
        if compare is not None:
            return ["cmp", *compare]
        memory_cmp = _decode_cmp_mem(text, insn.get("addr", 0), insn.get("size", 0))
        return [*memory_cmp] if memory_cmp is not None else None
    if kind == "acmp":
        test = _decode_two_operand(text, "test")
        return ["test", *test] if test is not None else None
    if kind in ("shl", "shr", "sar"):
        shift = _decode_shift(text)
        return ["shift", *shift] if shift is not None else None
    if kind == "mul":
        imul = _decode_imul(text)
        if imul is not None:
            return ["imul", *imul]
        imul3 = _decode_imul3(text)
        return ["imul3", *imul3] if imul3 is not None else None
    if kind == "lea":
        lea = _decode_lea(text, insn.get("addr", 0), insn.get("size", 0))
        if lea is not None:
            return [*lea]
        lea_indexed = _decode_lea_indexed(text)
        return [*lea_indexed] if lea_indexed is not None else None
    if kind in ("push", "upush", "rpush"):
        push = _decode_push(text)
        return [*push] if push is not None else None
    if kind in ("pop", "rpop"):
        leave = _decode_leave(text)
        if leave is not None:
            return [*leave]
        pop = _decode_pop(text)
        return [*pop] if pop is not None else None
    if kind == "jmp":
        return ["jmp", insn.get("jump", -1)]
    if kind == "cjmp":
        condition = _CONDITION.get(text.split(None, 1)[0].lower())
        return ["jcc", condition, insn.get("jump", -1)] if condition is not None else None
    return None


def _writes_register(item: tuple[Any, ...]) -> int | None:
    """The logical register slot an item writes, or ``None`` if it writes no GP
    register (a comparison, a memory store, a stack adjustment, or a branch).

    Used by the stack-balance guard to invalidate a frame-pointer snapshot when
    the snapshot register is overwritten before a ``mov rsp, reg`` consumes it.
    """
    kind = item[0]
    if kind == "op":
        op: VirtualizedOp = item[1]
        return op.dst_index
    if kind in (
        "imul",
        "imul3",
        "pop",
        "movfromrsp",
        "leave",
        "load",
        "riprel_load",
        "lea",
        "learip",
        "leaidx",
        "leaidxnb",
    ):
        return int(item[1])
    if kind in ("shift", "opmem", "opriprel", "opmemidx", "incdec"):
        return int(item[2])
    if kind in ("movx", "movxidx"):
        return int(item[4])
    return None


def _stack_balanced(items: list[list[Any]]) -> bool:
    """Verify the region's virtual stack is balanced on every path.

    The VM force-restores the hardware rsp on exit, and the function's virtual
    stack traffic happens in a relocated scratch region, so a region is only safe
    if every path reaches each terminator with the stack at its entry depth and
    never underflows (which would read caller stack the VM never modelled). A
    forward dataflow tracks, per item, a byte depth and the frame-pointer
    snapshot ``(register, depth)`` taken by ``mov reg, rsp``: push/pop move 8
    bytes, ``add``/``sub rsp,imm`` move imm, and ``mov rsp,reg``/``leave`` restore
    the depth captured when ``reg`` last copied rsp (rejecting if that register
    was overwritten meanwhile). Conflicting depths, an underflow, or a non-zero
    depth at a terminator rejects the region (left native).
    """
    # Per item: (byte depth, frame-pointer snapshot (register, depth) or None).
    state: list[tuple[int, tuple[int, int] | None] | None] = [None] * len(items)
    state[0] = (0, None)
    work = [0]
    while work:
        i = work.pop()
        current = state[i]
        assert current is not None  # only assigned indices enter the worklist
        depth, snapshot = current
        item = items[i]
        kind = item[0]
        if kind in ("push", "pushi"):
            out_depth = depth + 8
        elif kind == "pop":
            out_depth = depth - 8
        elif kind == "rspadj":
            out_depth = depth + (item[2] if item[1] == "sub" else -item[2])
        elif kind == "movtorsp":
            if snapshot is None or item[1] != snapshot[0]:
                return False  # restoring rsp from a register with no live snapshot
            out_depth = snapshot[1]
        elif kind == "leave":
            if snapshot is None or item[1] != snapshot[0]:
                return False
            out_depth = snapshot[1] - 8  # mov rsp,rbp then pop rbp
        else:
            out_depth = depth
        if out_depth < 0:
            return False  # stack underflow
        if kind == "movfromrsp":
            out_snapshot = (int(item[1]), depth)
        else:
            written = _writes_register(tuple(item))
            out_snapshot = None if (snapshot is not None and written == snapshot[0]) else snapshot
        if kind == "exit":
            if depth != 0:
                return False  # unbalanced stack at a terminator
            continue
        if kind == "jmp":
            successors = [item[1]]
        elif kind == "jcc":
            successors = [i + 1, item[2]]
        else:
            successors = [i + 1]
        for nxt in successors:
            if not 0 <= nxt < len(items):
                return False
            existing = state[nxt]
            if existing is None:
                state[nxt] = (out_depth, out_snapshot)
                work.append(nxt)
            else:
                if existing[0] != out_depth:
                    return False  # paths disagree on stack depth
                merged_snapshot = existing[1] if existing[1] == out_snapshot else None
                if merged_snapshot != existing[1]:
                    state[nxt] = (existing[0], merged_snapshot)
                    work.append(nxt)  # snapshot weakened; re-propagate
    return True


# Items that fully overwrite every readable arithmetic flag (CF, OF, SF, ZF, PF;
# AF is never read by any conditional jump). They kill an upstream flag value.
_FLAG_KILLER_KINDS = frozenset(
    {"cmp", "test", "cmpmem", "cmpriprel", "opmem", "opriprel", "opmemdst", "opmemdstrip", "opmemidx"}
)


def _flag_successors(items: list[list[Any]], i: int) -> list[int]:
    kind = items[i][0]
    if kind == "exit":
        return []
    if kind == "jmp":
        return [items[i][1]]
    if kind == "jcc":
        return [i + 1, items[i][2]]
    return [i + 1]


_MBA_OP_MNEMONICS = frozenset({"add", "sub", "xor", "and", "or"})


def _flag_dead_op_indices(items: list[list[Any]]) -> set[int]:
    """Indices of ``add``/``sub`` op items whose flags are dead on every path.

    A conditional jump (``jcc``) is the only instruction in the virtualizable
    subset that reads flags, so an op's flags are dead iff no reachable ``jcc``
    reads them before a full flag-killer (``cmp``/``sub``/...) overwrites them.
    The analysis is conservative — every ``jcc`` is treated as reading all flags
    and every terminator as keeping them live — so an add is only marked when its
    flags are provably unread, never the reverse.
    """
    n = len(items)

    def fixed_needed_in(i: int) -> bool | None:
        kind = items[i][0]
        if kind in ("jcc", "exit"):
            return True  # jcc reads flags; exit conservatively keeps them live
        if kind in _FLAG_KILLER_KINDS:
            return False
        if kind == "op" and items[i][1].mnemonic != "mov":
            return False  # add/sub/xor/and/or overwrite every readable flag
        return None  # everything else neither reads nor fully kills flags

    needed_in = [False] * n
    changed = True
    while changed:
        changed = False
        for i in range(n):
            fixed = fixed_needed_in(i)
            value = fixed if fixed is not None else any(needed_in[s] for s in _flag_successors(items, i))
            if value != needed_in[i]:
                needed_in[i] = value
                changed = True

    dead = set()
    for i in range(n):
        if items[i][0] == "op" and items[i][1].mnemonic in _MBA_OP_MNEMONICS:
            if not any(needed_in[s] for s in _flag_successors(items, i)):
                dead.add(i)
    return dead


# Mean junk VM instructions inserted per real item. ``mov reg, reg`` is a perfect
# identity (writes a slot with its own value, sets no flags), so it is
# semantics-preserving for any register at any position - no liveness analysis
# needed - yet it executes a real handler and pads the bytecode with operations a
# devirtualizer cannot distinguish from the program's own. Kept modest so the
# per-run execution cost (and a looping run's total) stays bounded.
_JUNK_OP_PROBABILITY = 0.35


def _inject_junk_movs(items: list[list[Any]], rng: random.Random) -> list[list[Any]]:
    """Sprinkle identity ``mov reg, reg`` items through the resolved item list and
    remap every branch target index to its new position.

    Branches store their target as an item index; inserting items shifts those
    indices, so a position map is built as the new list is assembled and applied to
    every ``jmp``/``jcc`` afterward. Junk is never itself a branch target.
    """
    junk_regs = [index for index in range(len(GP_REGISTERS)) if index != RSP_INDEX]
    new_items: list[list[Any]] = []
    old_to_new: dict[int, int] = {}
    for old_index, item in enumerate(items):
        while rng.random() < _JUNK_OP_PROBABILITY:
            reg = rng.choice(junk_regs)
            new_items.append(["op", VirtualizedOp("mov", reg, reg, False, 64)])
        old_to_new[old_index] = len(new_items)
        new_items.append(item)
    for item in new_items:
        if item[0] == "jmp":
            item[1] = old_to_new[item[1]]
        elif item[0] == "jcc":
            item[2] = old_to_new[item[2]]
    return new_items


def extract_region(instructions: list[dict[str, Any]], rng: random.Random | None = None) -> Region | None:
    """Lower a function's linear instruction list into a :class:`Region`.

    Returns ``None`` unless every instruction is a register op, comparison,
    ``nop``, in-function branch, or a terminator (``ret``/``syscall``). Any
    number of terminators is allowed; each becomes a distinct VM exit.
    """
    if not instructions:
        return None

    exit_addrs = sorted({insn["addr"] for insn in instructions if insn.get("type") in ("ret", "swi", "syscall")})
    if not exit_addrs:
        return None
    exit_set = set(exit_addrs)
    body = [insn for insn in instructions if insn["addr"] not in exit_set]
    if not body:
        return None

    # Phase 1: build items, recording each instruction's item index and storing
    # branch/fall-through targets as native addresses (resolved in phase 2). A
    # target that is a terminator address denotes that terminator's exit item.
    items: list[list[Any]] = []
    item_index_of: dict[int, int] = {}
    op_keys: set[str] = set()
    for insn in body:
        item = _classify(insn)
        if item is None:
            return None
        item_index_of[insn["addr"]] = len(items)
        items.append(item)
        key = _op_key(tuple(item))
        if key is not None:
            op_keys.add(key)
        # Fall-through into a terminator (everything except an unconditional jmp).
        next_addr = insn["addr"] + insn.get("size", 0)
        if item[0] != "jmp" and next_addr in exit_set:
            items.append(["jmp", next_addr])
            op_keys.add("jmp")

    exit_index_of: dict[int, int] = {}
    for addr in exit_addrs:
        exit_index_of[addr] = len(items)
        items.append(["exit", addr])
        op_keys.add(f"exit_{addr}")
    if any(item[0] == "jmp" for item in items):
        op_keys.add("jmp")

    def resolve(target: int) -> int | None:
        if target in exit_index_of:
            return exit_index_of[target]
        return item_index_of.get(target)

    # Phase 2: resolve branch target addresses to item indices.
    for item in items:
        if item[0] == "jmp":
            resolved = resolve(item[1])
            if resolved is None:
                return None
            item[1] = resolved
        elif item[0] == "jcc":
            resolved = resolve(item[2])
            if resolved is None:
                return None
            item[2] = resolved

    if not _stack_balanced(items):
        return None

    # Flag-liveness: an add whose flags are never read becomes an MBA handler
    # (no literal add, no flag capture). Runs before junk injection so the analysis
    # sees only the program's real items.
    for index in _flag_dead_op_indices(items):
        items[index][0] = "opmba"
    # Junk identity movs (semantics-preserving) padding the bytecode; done after the
    # stack/flag analyses, which the junk does not affect. Rebuild op_keys for the
    # rewritten + augmented items.
    if rng is not None:
        items = _inject_junk_movs(items, rng)
    op_keys = {key for item in items if (key := _op_key(tuple(item))) is not None}

    body_ranges = [(insn["addr"], insn.get("size", 0)) for insn in body]
    return Region([tuple(item) for item in items], exit_addrs[0], body[0]["addr"], op_keys, body_ranges)


def build_region_scheme(region: Region, rng: random.Random) -> RegionScheme:
    """Assign each handler a dense opcode index plus a bytecode key.

    Opcodes are a per-instance permutation of ``0..N-1`` (N = handler count):
    they index the dispatch table directly, so two builds still share no
    opcode->operation mapping (the permutation differs), but the table stays
    N entries wide instead of a full 256.
    """
    keys = sorted(region.op_keys)
    # Give each handler one or two interchangeable instances; the total stays
    # within a byte so opcodes still index the table directly.
    multiplicity = {key: rng.randint(1, 2) for key in keys}
    total = sum(multiplicity.values())
    indices = rng.sample(range(total), total)
    dup: dict[str, tuple[int, ...]] = {}
    cursor = 0
    for key in keys:
        count = multiplicity[key]
        dup[key] = tuple(indices[cursor : cursor + count])
        cursor += count
    slot_perm = tuple(rng.sample(range(len(GP_REGISTERS)), len(GP_REGISTERS)))
    return RegionScheme(dup, rng.randrange(1, 256), rng.randrange(1 << 31), slot_perm, rng.randrange(1, 1 << 32))
