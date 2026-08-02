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
from r2morph.mutations.code_virtualization_engine_common import _OPCODE_BUDGET
from r2morph.mutations.code_virtualization_region_decoders import (
    _decode_cmp_mem,
    _decode_fp_arith,
    _decode_fp_arith_idx,
    _decode_fp_arith_mem,
    _decode_fp_arith_riprel,
    _decode_fp_compare,
    _decode_fp_convert,
    _decode_fp_indexed,
    _decode_fp_mem,
    _decode_fp_move,
    _decode_fp_packed_arith,
    _decode_fp_packed_arith_idx,
    _decode_fp_packed_arith_mem,
    _decode_fp_packed_arith_riprel,
    _decode_fp_packed_indexed,
    _decode_fp_packed_mem,
    _decode_fp_packed_riprel,
    _decode_fp_riprel,
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
    _parse_indexed_operand,
    _parse_mem_operand,
    _parse_riprel_operand,
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

# r2 instruction types for a register/memory-indirect jump (jmp reg / jmp [mem]) -
# the defining dispatch instruction of a computed-goto interpreter.
_COMPUTED_JUMP_TYPES = ("ujmp", "rjmp", "ijmp", "mjmp")


def _classify(insn: dict[str, Any], allow_computed_jump: bool = False) -> list[Any] | None:
    """Build the VM item for one body instruction, or ``None`` if unsupported.

    ``allow_computed_jump`` opts in to lowering a register-indirect jump to an
    ``ijmp`` item. It is off by default so the straight-line region contract keeps
    rejecting computed jumps; only the dispatch-region contract enables it.
    """
    kind = insn.get("type", "")
    text = insn.get("opcode", "")
    # int<->float conversions are type "null" and inconsistently typed family
    # (the r64 cvtsi2sd is even family "cpu"), so they are matched by mnemonic
    # ahead of the family gate; the decoder returns None for non-conversions.
    convert = _decode_fp_convert(text)
    if convert is not None:
        return [*convert]
    if insn.get("family") == "vec":
        # SSE/FP ops share their GP twin's ``type`` (movsd->mov, addsd->add) but
        # carry family "vec". Route them here first: scalar FP load/store is
        # virtualized, everything else vec is left native (conservative).
        fp_mem = _decode_fp_mem(text)
        if fp_mem is not None:
            return [*fp_mem]
        fp_indexed = _decode_fp_indexed(text)
        if fp_indexed is not None:
            return [*fp_indexed]
        fp_riprel = _decode_fp_riprel(text, insn.get("addr", 0), insn.get("size", 0))
        if fp_riprel is not None:
            return [*fp_riprel]
        fp_arith = _decode_fp_arith(text)
        if fp_arith is not None:
            return [*fp_arith]
        fp_arith_mem = _decode_fp_arith_mem(text)
        if fp_arith_mem is not None:
            return [*fp_arith_mem]
        fp_arith_riprel = _decode_fp_arith_riprel(text, insn.get("addr", 0), insn.get("size", 0))
        if fp_arith_riprel is not None:
            return [*fp_arith_riprel]
        fp_arith_idx = _decode_fp_arith_idx(text)
        if fp_arith_idx is not None:
            return [*fp_arith_idx]
        fp_compare = _decode_fp_compare(text)
        if fp_compare is not None:
            return [*fp_compare]
        fp_move = _decode_fp_move(text)
        if fp_move is not None:
            return [*fp_move]
        fp_packed = _decode_fp_packed_arith(text)
        if fp_packed is not None:
            return [*fp_packed]
        fp_packed_arith_mem = _decode_fp_packed_arith_mem(text)
        if fp_packed_arith_mem is not None:
            return [*fp_packed_arith_mem]
        fp_packed_arith_riprel = _decode_fp_packed_arith_riprel(text, insn.get("addr", 0), insn.get("size", 0))
        if fp_packed_arith_riprel is not None:
            return [*fp_packed_arith_riprel]
        fp_packed_arith_idx = _decode_fp_packed_arith_idx(text)
        if fp_packed_arith_idx is not None:
            return [*fp_packed_arith_idx]
        fp_packed_mem = _decode_fp_packed_mem(text)
        if fp_packed_mem is not None:
            return [*fp_packed_mem]
        fp_packed_indexed = _decode_fp_packed_indexed(text)
        if fp_packed_indexed is not None:
            return [*fp_packed_indexed]
        fp_packed_riprel = _decode_fp_packed_riprel(text, insn.get("addr", 0), insn.get("size", 0))
        return [*fp_packed_riprel] if fp_packed_riprel is not None else None
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
    if allow_computed_jump:
        # Native pushfq/popfq bracketing the dispatch: the region synthesizes an
        # operation's flags into the flags slot (never native RFLAGS), so a native
        # flag save/restore is modelled as a copy of that slot to/from the vstack
        # (fsave/frestore), not a native push of RFLAGS. Gated to the dispatch-region
        # contract; matched save/restore is assumed (the flag-preservation idiom that
        # is the only shape where flag state crosses the computed jump), so it stays
        # vstack-balanced across the bracket. Any other flag use fails the branches
        # below and is left native.
        mnemonic = text.split()[0].lower() if text else ""
        if mnemonic in ("pushfq", "pushfd", "pushf"):
            return ["fsave"]
        if mnemonic in ("popfq", "popfd", "popf"):
            return ["frestore"]
    if kind in ("push", "upush", "rpush"):
        push = _decode_push(text)
        return [*push] if push is not None else None
    if kind in ("pop", "rpop"):
        leave = _decode_leave(text)
        if leave is not None:
            return [*leave]
        pop = _decode_pop(text)
        return [*pop] if pop is not None else None
    if kind == "call":
        # Only a direct call with a resolvable target is virtualizable; an
        # indirect call (call rax / call [mem]) has type "ucall"/"rcall" and never
        # reaches here, and a direct call with no resolved target is left native.
        target = insn.get("jump", -1)
        return ["call", target] if isinstance(target, int) and target > 0 else None
    if kind == "rcall":
        # Register-indirect call (call reg): the target is the program value of a
        # GP register, read from its frame slot at runtime. Memory-indirect calls
        # (type ucall/mcall) are not handled and stay native.
        parts = text.split()
        if len(parts) == 2 and parts[1] in GP_REGISTERS and parts[1] != "rsp":
            return ["icall", GP_REGISTERS.index(parts[1])]
        return None
    if kind == "ircall":
        # Memory-indirect call (call qword [base+disp] / [rip+disp]): the target
        # pointer is loaded from memory at runtime - vtable and IAT/GOT dispatch.
        # The addressing reuses the load handlers' machinery; indexed forms stay
        # native for now.
        operand = text.split(None, 1)[1] if " " in text else ""
        mem = _parse_mem_operand(operand)
        if mem is not None:
            base_slot, disp, _width = mem
            return ["callmem", base_slot, disp]
        riprel_ptr = _parse_riprel_operand(operand, insn.get("addr", 0), insn.get("size", 0))
        if riprel_ptr is not None:
            return ["callmemrip", riprel_ptr[0]]
        return None
    if kind == "ucall":
        # Indexed memory-indirect call (call qword [base+index*scale+disp]):
        # function-pointer table / array-of-vtables dispatch. A base is required;
        # other unresolved indirect forms stay native.
        operand = text.split(None, 1)[1] if " " in text else ""
        indexed = _parse_indexed_operand(operand)
        if indexed is not None:
            base_slot, index_slot, scale_shift, idx_disp = indexed
            return ["callmemidx", base_slot, index_slot, scale_shift, idx_disp]
        return None
    if kind == "jmp":
        return ["jmp", insn.get("jump", -1)]
    if allow_computed_jump and kind in _COMPUTED_JUMP_TYPES:
        # Register-indirect jump (jmp reg): a computed control transfer whose
        # target is the program value of a GP register, read from its frame slot
        # at runtime - the defining dispatch instruction of a computed-goto
        # interpreter. Modelled on the register-indirect call (icall) above.
        # Memory-indirect computed jumps (jmp [table+idx*scale]) are decomposed by
        # the dispatch-region contract into an indexed load plus this register
        # form, so only the bare-register operand is taken here.
        parts = text.split()
        if len(parts) == 2 and parts[1] in GP_REGISTERS and parts[1] != "rsp":
            return ["ijmp", GP_REGISTERS.index(parts[1])]
        return None
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
    if kind in ("op", "opmba", "opsynth"):
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
    {
        "cmp",
        "test",
        "cmpmem",
        "cmpriprel",
        "opmem",
        "opriprel",
        "opmemdst",
        "opmemdstrip",
        "opmemidx",
        "call",
        "icall",
        "callmem",
        "callmemrip",
        "callmemidx",
    }
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

    A conditional jump (``jcc``) and a flag save (``fsave``, the virtualized
    ``pushfq``) are the flag readers in the virtualizable subset, so an op's flags
    are dead iff no reachable reader consumes them before a full flag-killer
    (``cmp``/``sub``/...) overwrites them.
    The analysis is conservative — every ``jcc`` is treated as reading all flags
    and every terminator as keeping them live — so an add is only marked when its
    flags are provably unread, never the reverse.
    """
    n = len(items)

    def fixed_needed_in(i: int) -> bool | None:
        kind = items[i][0]
        if kind in ("jcc", "exit", "fsave"):
            return True  # jcc/fsave read flags; exit conservatively keeps them live
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


def _lower_arith_to_microops(items: list[list[Any]], index_map: dict[int, int] | None = None) -> list[list[Any]]:
    """Lower each arithmetic and base+disp memory item into virtual-stack micro-ops
    and remap every branch target index to its new position.

    A single handler that computes a whole native op is a fingerprint; lowering it to
    ``vpush``/``vload``/``vbinop*``/``vpop``/``vstore`` reuses a handful of stack
    primitives across every op instead. Arithmetic pushes dst then src, so the fold
    sees ``a == dst, b == src``; ``vpop`` writes the result back to dst. The fold kind
    depends on flag liveness: ``opmba`` (flags proven dead) folds with ``vbinop`` (no
    flag capture); ``opsynth`` (flags read by a later branch) folds with ``vbinopsynth``
    (which also synthesizes the readable flags). Base+disp memory lowers too: a load
    is ``vload``/``vpop``, a store ``vpush``/``vstore``, and a mem-source arith op
    ``vpush``/``vload``/``vbinopsynth``/``vpop`` (mem forms are always flag-synthesizing
    today). Rip-relative and scaled-index memory keep their single handlers.

    Branches store their target as an item index; expanding an item shifts those
    indices, so a position map is built as the new list is assembled and applied to
    every ``jmp``/``jcc`` afterward. A branch can only target the start of an item, so
    it maps to the sequence's first micro-op (never an interior one).
    """
    fold_of = {"opmba": "vbinop", "opsynth": "vbinopsynth"}
    new_items: list[list[Any]] = []
    old_to_new: dict[int, int] = {}
    for old_index, item in enumerate(items):
        old_to_new[old_index] = len(new_items)
        kind = item[0]
        fold = fold_of.get(kind)
        if fold is not None:
            op = item[1]
            new_items.append(["vpush", op.dst_index])
            if op.is_immediate:
                new_items.append(["vpushi", op.value, op.width])
            else:
                new_items.append(["vpush", op.value])
            new_items.append([fold, op.mnemonic, op.width])
            new_items.append(["vpop", op.dst_index])
        elif kind == "load":  # mov reg, [base+disp]
            _, reg, base, disp, width = item
            new_items.append(["vload", base, disp, width])
            new_items.append(["vpop", reg])
        elif kind == "store":  # mov [base+disp], reg
            _, reg, base, disp, width = item
            new_items.append(["vpush", reg])
            new_items.append(["vstore", base, disp, width])
        elif kind == "opmem":  # <op> reg, [base+disp] -- reg is src and dst
            _, mnemonic, reg, base, disp, width = item
            new_items.append(["vpush", reg])
            new_items.append(["vload", base, disp, width])
            # opmem is always flag-synthesizing today, so fold with vbinopsynth.
            new_items.append(["vbinopsynth", mnemonic, width])
            new_items.append(["vpop", reg])
        elif kind == "shift":
            # ("shift", mnemonic, slot, count, width): push the register, shift the
            # top cell by the immediate count (capturing flags), pop the result back.
            _, mnemonic, slot, count, width = item
            new_items.append(["vpush", slot])
            new_items.append(["vshift", mnemonic, count, width])
            new_items.append(["vpop", slot])
        elif kind == "opmemidx":  # <op> reg, [base+index*scale+disp] -- reg is src and dst
            _, mnemonic, reg, base, index, shift, disp, width = item
            new_items.append(["vpush", reg])
            new_items.append(["vloadidx", base, index, shift, disp, width])
            # opmemidx is always flag-synthesizing today, so fold with vbinopsynth.
            new_items.append(["vbinopsynth", mnemonic, width])
            new_items.append(["vpop", reg])
        elif kind == "opmemdst":  # <op> [base+disp], reg -- read-modify-write
            # The result is stored back to memory, so vload the current value, fold it
            # with the register, and vstore the result. The address is recomputed by
            # both vload and vstore, which is sound: base+disp is deterministic and no
            # intervening micro-op writes the base slot (the op writes memory, not the
            # base register), so both computations read the same address.
            _, mnemonic, reg, base, disp, width = item
            new_items.append(["vload", base, disp, width])
            new_items.append(["vpush", reg])
            new_items.append(["vbinopsynth", mnemonic, width])
            new_items.append(["vstore", base, disp, width])
        elif kind in ("cmp", "test"):
            # ("cmp"|"test", slot, value, is_immediate, width): push both operands,
            # then synthesize the flags off the stack (no result stored).
            _, slot, value, is_immediate, width = item
            new_items.append(["vpush", slot])
            new_items.append(["vpushi", value, width] if is_immediate else ["vpush", value])
            new_items.append(["vcmpsynth", kind, width])
        elif kind == "cmpmem":  # cmp reg, [base+disp]
            _, reg, base, disp, width = item
            new_items.append(["vpush", reg])
            new_items.append(["vload", base, disp, width])
            new_items.append(["vcmpsynth", "cmp", width])
        elif kind == "cmpriprel":  # cmp reg, [rip+disp] -- a global
            _, reg, target, width = item
            new_items.append(["vpush", reg])
            new_items.append(["vloadrip", target, width])
            new_items.append(["vcmpsynth", "cmp", width])
        elif kind == "riprel_load":  # mov reg, [rip+disp]
            _, reg, target, width = item
            new_items.append(["vloadrip", target, width])
            new_items.append(["vpop", reg])
        elif kind == "riprel_store":  # mov [rip+disp], reg
            _, reg, target, width = item
            new_items.append(["vpush", reg])
            new_items.append(["vstorerip", target, width])
        elif kind == "opriprel":  # <op> reg, [rip+disp] -- reg is src and dst
            _, mnemonic, reg, target, width = item
            new_items.append(["vpush", reg])
            new_items.append(["vloadrip", target, width])
            # opriprel is always flag-synthesizing today, so fold with vbinopsynth.
            new_items.append(["vbinopsynth", mnemonic, width])
            new_items.append(["vpop", reg])
        elif kind == "opmemdstrip":  # <op> [rip+disp], reg -- read-modify-write global
            _, mnemonic, reg, target, width = item
            new_items.append(["vloadrip", target, width])
            new_items.append(["vpush", reg])
            new_items.append(["vbinopsynth", mnemonic, width])
            new_items.append(["vstorerip", target, width])
        else:
            new_items.append(item)
    for item in new_items:
        if item[0] == "jmp":
            item[1] = old_to_new[item[1]]
        elif item[0] == "jcc":
            item[2] = old_to_new[item[2]]
    _remap_index_map(index_map, old_to_new)
    return new_items


def _remap_index_map(index_map: dict[int, int] | None, old_to_new: dict[int, int]) -> None:
    """Remap a native-address -> item-index map through a lowering's position shift.

    A computed jump's target map stores item indices that move when items are
    lowered or junk is inserted, exactly like branch targets do; this reapplies the
    same shift so the map keeps pointing at the right items.
    """
    if index_map is None:
        return
    for addr, old_index in list(index_map.items()):
        index_map[addr] = old_to_new[old_index]


def _inject_junk_movs(
    items: list[list[Any]], rng: random.Random, index_map: dict[int, int] | None = None
) -> list[list[Any]]:
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
    _remap_index_map(index_map, old_to_new)
    return new_items


def extract_region(
    instructions: list[dict[str, Any]], rng: random.Random | None = None, allow_computed_jump: bool = False
) -> Region | None:
    """Lower a function's linear instruction list into a :class:`Region`.

    Returns ``None`` unless every instruction is a register op, comparison,
    ``nop``, in-function branch, or a terminator (``ret``/``syscall``). Any
    number of terminators is allowed; each becomes a distinct VM exit.

    ``allow_computed_jump`` opts in to the dispatch-region contract: a register-
    indirect jump is lowered to an ``ijmp`` whose runtime target re-enters the VM
    via a target map (native address -> item index) built here. It is off by
    default so the straight-line contract and its guards are unchanged.
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
        item = _classify(insn, allow_computed_jump=allow_computed_jump)
        if item is None:
            return None
        item_index_of[insn["addr"]] = len(items)
        items.append(item)
        key = _op_key(tuple(item))
        if key is not None:
            op_keys.add(key)
        # Fall-through into a terminator (everything except an unconditional jump -
        # direct or computed - which never falls through).
        next_addr = insn["addr"] + insn.get("size", 0)
        if item[0] not in ("jmp", "ijmp") and next_addr in exit_set:
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

    # A call whose target lands inside this function's own span would either
    # recurse into the trampoline or hit a body byte that the dead-body fill
    # overwrites; only out-of-function direct calls are virtualizable here.
    func_lo = min(insn["addr"] for insn in instructions)
    func_hi = max(insn["addr"] + insn.get("size", 0) for insn in instructions)
    if any(item[0] == "call" and func_lo <= item[1] < func_hi for item in items):
        return None

    if not _stack_balanced(items):
        return None

    # Flag-liveness: an add whose flags are never read becomes an MBA handler
    # (no literal add, no flag capture). Runs before junk injection so the analysis
    # sees only the program's real items.
    for index in _flag_dead_op_indices(items):
        items[index][0] = "opmba"
    # A flag-LIVE arithmetic/boolean op (not marked opmba above) becomes opsynth:
    # the result is computed by MBA and the flags are synthesized by hand, so the
    # handler contains no flag-setting native arithmetic even when a later branch
    # reads its flags.
    for index, item in enumerate(items):
        if item[0] == "op" and item[1].mnemonic in _MBA_OP_MNEMONICS:
            items[index][0] = "opsynth"
    # Lower each arithmetic op (flag-dead opmba and flag-live opsynth) to virtual-stack
    # micro-ops so no handler maps 1:1 to a native mnemonic. Runs after the flag/stack
    # analyses (which see only the program's real items) and before junk injection.
    # A computed jump (ijmp) resolves its target at runtime to a native address in
    # this region; map every body instruction address to its item index so the ijmp
    # handler can re-enter the VM at the virtualized target. Threaded through the
    # lowering and junk passes so the indices stay correct as items shift. Only built
    # when the region actually contains a computed jump; otherwise the map is empty
    # and the region's blob is byte-identical to the straight-line contract's.
    has_computed_jump = any(item[0] == "ijmp" for item in items)
    target_map: dict[int, int] | None = dict(item_index_of) if has_computed_jump else None

    items = _lower_arith_to_microops(items, target_map)
    # Junk identity movs (semantics-preserving) padding the bytecode; done after the
    # stack/flag analyses, which the junk does not affect. Rebuild op_keys for the
    # rewritten + augmented items.
    if rng is not None:
        items = _inject_junk_movs(items, rng, target_map)
    op_keys = {key for item in items if (key := _op_key(tuple(item))) is not None}

    body_ranges = [(insn["addr"], insn.get("size", 0)) for insn in body]
    return Region([tuple(item) for item in items], exit_addrs[0], body[0]["addr"], op_keys, body_ranges, target_map)


def build_region_scheme(region: Region, rng: random.Random) -> RegionScheme:
    """Assign each handler a dense opcode index plus a bytecode key.

    Opcodes are a per-instance permutation of ``0..N-1`` (N = handler count):
    they index the dispatch table directly, so two builds still share no
    opcode->operation mapping (the permutation differs), but the table stays
    N entries wide instead of a full 256.
    """
    keys = sorted(region.op_keys)
    if len(keys) > _OPCODE_BUDGET:
        raise ValueError(f"{len(keys)} op-keys exceed the {_OPCODE_BUDGET}-value single-byte opcode budget")
    # Give each handler one or two interchangeable instances; the total must stay
    # within a byte so opcodes still index the table directly and a value remains
    # above it for the dispatch bounds-guard exit. If duplication would overflow
    # the budget, downgrade duplicated handlers (rng-ordered) until it fits; the
    # clamp only draws extra randomness when it triggers, so schemes that already
    # fit are byte-identical to before.
    multiplicity = {key: rng.randint(1, 2) for key in keys}
    total = sum(multiplicity.values())
    if total > _OPCODE_BUDGET:
        downgradable = [key for key in keys if multiplicity[key] == 2]
        rng.shuffle(downgradable)
        for key in downgradable:
            if total <= _OPCODE_BUDGET:
                break
            multiplicity[key] = 1
            total -= 1
    indices = rng.sample(range(total), total)
    dup: dict[str, tuple[int, ...]] = {}
    cursor = 0
    for key in keys:
        count = multiplicity[key]
        dup[key] = tuple(indices[cursor : cursor + count])
        cursor += count
    slot_perm = tuple(rng.sample(range(len(GP_REGISTERS)), len(GP_REGISTERS)))
    xor_key = rng.randrange(1, 256)
    junk_seed = rng.randrange(1 << 31)
    table_key = rng.randrange(1, 1 << 32)
    field_perm = rng.randrange(1, 1 << 31)
    body_seed = rng.randrange(1 << 31)
    # Drawn last so adding the frame-slot relocation does not shift any earlier
    # field's value for a given seed. The checksum and flags slots are placed in the
    # frame's free middle, qword-aligned and distinct: the checksum in [0x88, 0x100)
    # (never 0x80, which stays reserved as the flag handlers' rendered slot), and the
    # flags slot anywhere in [0x80, 0x100) except the checksum's slot.
    checksum_offset = rng.randrange(0x88, 0x100, 8)
    flags_offset = rng.choice([off for off in range(0x80, 0x100, 8) if off != checksum_offset])
    # Drawn last so adding the ISA-personality seed does not shift any earlier field's
    # value for a given seed. Selects this build's handler-implementation personality
    # (the flag-synthesis spelling; see code_virtualization_region_isa).
    isa_seed = rng.randrange(1 << 31)
    return RegionScheme(
        dup,
        xor_key,
        junk_seed,
        slot_perm,
        table_key,
        field_perm,
        body_seed,
        checksum_offset,
        flags_offset,
        isa_seed,
    )
