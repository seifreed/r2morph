"""Shared base layer for the code-virtualization engine.

Constants, op-key enumeration, the per-instance :class:`VMScheme`, the
junk/opaque-predicate emitters, and width helpers - everything both the
bytecode encoder and the interpreter codegen depend on. Kept free of any
dependency on its sibling engine modules so the split forms a cycle-free
layering (common <- models <- codegen <- aggregator).
"""

from __future__ import annotations

import struct
from collections.abc import Hashable, Sequence
from dataclasses import dataclass
from typing import TypeVar

import r2morph.core.randomness as random
from r2morph.core.constants import ARCH_BITS_64

_OpKey = TypeVar("_OpKey", bound=Hashable)
_LIVE_OPAQUE_PROBABILITY = 0.5

# ModR/M register order; index is the VM register-context slot.
GP_REGISTERS: tuple[str, ...] = (
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)
REGISTER_INDEX: dict[str, int] = {name: idx for idx, name in enumerate(GP_REGISTERS)}
RSP_INDEX = REGISTER_INDEX["rsp"]


def gp_save_order(seed: int) -> tuple[int, ...]:
    """Return a reproducible order for saving the non-stack GP registers."""
    order = list(range(len(GP_REGISTERS)))
    random.Random(seed).shuffle(order)
    return tuple(index for index in order if index != RSP_INDEX)


# 32-bit register spellings share a context slot with their 64-bit base; a
# 32-bit write zero-extends into the full slot, matching x86-64 semantics.
REGISTER32_INDEX: dict[str, int] = {
    "eax": 0,
    "ecx": 1,
    "edx": 2,
    "ebx": 3,
    "esp": 4,
    "ebp": 5,
    "esi": 6,
    "edi": 7,
    "r8d": 8,
    "r9d": 9,
    "r10d": 10,
    "r11d": 11,
    "r12d": 12,
    "r13d": 13,
    "r14d": 14,
    "r15d": 15,
}

_MNEMONIC_ORDER: tuple[str, ...] = ("mov", "add", "sub", "xor", "and", "or")
# GP mnemonics that keep a single handler. The arithmetic ops (add/sub/xor/and/or)
# lower to micro-op sequences (see the micro-op kinds below) rather than one handler,
# so only ``mov`` needs a single-handler op-key; the arith mnemonics stay in
# _MNEMONIC_ORDER (and thus SUPPORTED_MNEMONICS) so decode still virtualizes them.
_GP_SINGLE_HANDLER_MNEMONICS: tuple[str, ...] = ("mov",)
# Bit-shift-by-immediate GP ops. Only the immediate-count form virtualizes: the
# ``shl reg, cl`` register-count form is rejected in decode by the operand width
# mismatch (cl is 8-bit), so no register-form handler is ever needed - hence these
# are keyed is_immediate=True only and kept out of _MNEMONIC_ORDER. Sound under the
# engine's flags-dead precondition (a shift clobbers flags like add/sub/xor do).
_SHIFT_KINDS: tuple[str, ...] = ("shl", "shr", "sar")
SUPPORTED_MNEMONICS: frozenset[str] = frozenset(_MNEMONIC_ORDER) | frozenset(_SHIFT_KINDS)

# Canonical operation keys (mnemonic, is_immediate, width). Register/immediate
# and 32/64-bit variants are distinct so the dispatcher never has to inspect
# operand encoding at runtime. The concrete opcode byte for each key is
# assigned per instance (see VMScheme), so two virtualized builds share no
# fixed opcode table to fingerprint.
# Memory operations. They reuse the (mnemonic, is_immediate, width) key shape with
# the kind as the "mnemonic" and is_immediate fixed False, so the dispatch-table,
# duplication and self-checksum machinery treat them uniformly; only the operand
# layout (reg slot + base slot + disp32) and the handler body differ, both keyed
# off the kind. ``load``/``store`` move reg <-> [base+disp]; ``mem<op>`` applies an
# arithmetic/boolean op with [base+disp] as the source (reg is source and dest).
_MEM_ARITH_MNEMONICS: tuple[str, ...] = ("add", "sub", "xor", "and", "or")
# ``lea`` computes [base+disp] into the destination without dereferencing. The
# ``*rip`` kinds reach a global via the bytecode base plus a stored offset; the
# handler strips the ``rip`` suffix and reuses the base kind's body with the
# rip-relative address prologue, so every base+disp form has a global counterpart.
_MEM_BASE_KINDS: tuple[str, ...] = ("load", "store", "lea", *tuple(f"mem{m}" for m in _MEM_ARITH_MNEMONICS))
# movzx/movsx of a byte/word from [base+disp], zero-/sign-extended into the dst.
# (No rip-relative counterpart: the decoder only produces the base+disp form.)
_MEM_MOVX_KINDS: tuple[str, ...] = ("movzxb", "movzxw", "movsxb", "movsxw")
# Indexed [base+index*scale+disp] forms (arrays). Loads, stores, lea,
# arithmetic, and byte/word extends reuse the base kind's body with the
# indexed address prologue (a 9-byte item: opcode+reg+base+index+scale+disp).
_MEM_IDX_KINDS: tuple[str, ...] = (
    "load",
    "store",
    "lea",
    *tuple(f"mem{m}" for m in _MEM_ARITH_MNEMONICS),
    *_MEM_MOVX_KINDS,
)
_MEM_OP_KINDS: tuple[str, ...] = (
    _MEM_BASE_KINDS
    + tuple(f"{kind}rip" for kind in _MEM_BASE_KINDS)
    + _MEM_MOVX_KINDS
    + tuple(f"{kind}idx" for kind in _MEM_IDX_KINDS)
    + tuple(f"{kind}idxnb" for kind in ("load", "store"))
)
# Scalar-FP memory moves: ``movsd``/``movss`` between an xmm register and
# ``[base+disp]``. They reuse the (kind, is_immediate, width) key shape and the
# reg/base/disp operand layout, but the ``reg`` field carries an xmm index (0-15,
# emitted raw, not slot-permuted) and the handler moves through the frame's xmm
# save area instead of a GP slot.
# The ``*rip`` kinds reach an FP global (a .rodata/.data constant) via the bytecode
# base plus a stored signed offset, exactly like the GP ``loadrip``/``storerip``;
# the handler strips the ``rip`` suffix and reuses the load/store body with the
# rip-relative address prologue. They reuse VirtualizedFpMemOp with base_index = -1
# and the disp field carrying the absolute target.
# The ``*idx`` kinds address an array element ``[base+index*scale+disp]`` (a[i]);
# the item is a 9-byte opcode+reg+base+index+scale+disp32, and the handler reuses
# the scaled-index address prologue.
_FP_MEM_KINDS: tuple[str, ...] = (
    "fpload",
    "fpstore",
    "fploadrip",
    "fpstorerip",
    "fploadidx",
    "fpstoreidx",
    "fploadidxnb",
    "fpstoreidxnb",
)
# Scalar-FP register-register arithmetic: addsd/subsd/mulsd/divsd (+ss). Each op
# is its own kind so the dispatcher selects the handler without inspecting the
# operands; the item carries two raw xmm indices (dst, src). ``fp{op}`` keys map
# back to the real add/sub/mul/div instruction in the handler.
_FP_ARITH_OPS: tuple[str, ...] = ("add", "sub", "mul", "div", "sqrt", "min", "max")
_FP_ARITH_KINDS: tuple[str, ...] = tuple(f"fp{op}" for op in _FP_ARITH_OPS)
# Int<->float conversions: cvtsi2sd/ss (int->float) and cvttsd2si/ss (float->int).
# The GP width is part of the kind ("cvti2f"/"cvtf2i" + "32"/"64") so the handler
# selects eax vs rax faithfully (a 32-bit cvtsi2sd converts only the int32; a
# 32-bit cvttsd2si saturates out-of-range doubles to 0x80000000). The op-key width
# carries the FP precision (sd=64, ss=32).
_FP_CONVERT_KINDS: tuple[str, ...] = tuple(
    f"{direction}{gp_width}" for direction in ("cvti2f", "cvtf2i") for gp_width in (64, 32)
)
# Scalar-FP arithmetic with a memory source (``addsd xmm, [base+disp]`` and the
# rip-relative ``addsd xmm, [rip+const]`` constant-pool form). Per op
# (fparithmem{add,sub,mul,div,sqrt,min,max}), each with a ``*rip`` counterpart; the base+disp
# form is a 7-byte reg/base/disp item, the rip form a 6-byte reg/offset item. The
# handler reuses the load/store address prologues, then issues the scalar op with
# the memory source directly.
_FP_ARITH_MEM_KINDS: tuple[str, ...] = (
    tuple(f"fparithmem{op}" for op in _FP_ARITH_OPS)
    + tuple(f"fparithmem{op}rip" for op in _FP_ARITH_OPS)
    + tuple(f"fparithmem{op}idx" for op in _FP_ARITH_OPS)
    + tuple(f"fparithmem{op}idxnb" for op in _FP_ARITH_OPS)
)
# Packed 128-bit SIMD: register-register arithmetic (addpd/addps + sub/mul/div, all
# lanes) and 128-bit ``[base+disp]`` load/store (movaps/movups/movapd/movupd). The
# op-key width is a nominal 128 (the ops are lane-agnostic 128-bit); the arith kind
# is the mnemonic itself, so the handler emits it directly. xmm slots are already
# 128-bit, so there is no frame change and the moves are always movups.
_FP_PACKED_WIDTH = 128
_FP_PACKED_ARITH_KINDS: tuple[str, ...] = (
    "addpd",
    "addps",
    "subpd",
    "subps",
    "mulpd",
    "mulps",
    "divpd",
    "divps",
    "sqrtpd",
    "sqrtps",
    "minpd",
    "minps",
    "maxpd",
    "maxps",
    "paddb",
    "psubb",
    "paddw",
    "psubw",
    "paddd",
    "psubd",
    "paddq",
    "psubq",
    "pmulld",
    "pminsd",
    "pmaxsd",
    "pcmpeqd",
    "pcmpeqb",
    "pcmpgtd",
    "pcmpgtb",
    "pslld",
    "psrld",
    "psrad",
    "paddusb",
    "psubusb",
    "paddusw",
    "psubusw",
    "pavgb",
    "pavgw",
    "psadbw",
    "pmaddwd",
    "pmulhuw",
    "pmulhw",
    "packuswb",
    "packssdw",
    "punpcklbw",
    "punpcklwd",
    "pand",
    "pandn",
    "por",
    "pxor",
    "andps",
    "andpd",
    "orps",
    "orpd",
    "xorps",
    "xorpd",
)
_FP_PACKED_VEX_ARITH_KINDS: tuple[str, ...] = ("fppackedvex",)
_FP_PACKED_VEX_OPERATIONS: tuple[str, ...] = (
    "vaddpd",
    "vaddps",
    "vsubpd",
    "vsubps",
    "vmulpd",
    "vmulps",
    "vdivpd",
    "vdivps",
    "vminpd",
    "vminps",
    "vmaxpd",
    "vmaxps",
    "vandpd",
    "vandps",
    "vorpd",
    "vorps",
    "vxorpd",
    "vxorps",
    "vpand",
    "vpandn",
    "vpor",
    "vpxor",
    "vpaddb",
    "vpsubb",
    "vpaddw",
    "vpsubw",
    "vpaddd",
    "vpsubd",
    "vpaddq",
    "vpsubq",
    "vpslld",
    "vpsrld",
    "vpsrad",
    "vpmulld",
    "vpminsd",
    "vpmaxsd",
    "vpcmpeqd",
    "vpcmpgtd",
    "vpcmpeqb",
    "vpcmpeqw",
    "vpcmpeqq",
    "vpcmpgtb",
    "vpcmpgtw",
    "vpcmpgtq",
    "vpaddusb",
    "vpsubusb",
    "vpaddusw",
    "vpsubusw",
    "vpavgb",
    "vpavgw",
    "vpsadbw",
    "vpmaddwd",
    "vpmulhuw",
    "vpmulhw",
    "vpackuswb",
    "vpackssdw",
    "vpunpcklbw",
    "vpunpcklwd",
    "vpshufb",
)
_FP_SCALAR_VEX_ARITH_KINDS: tuple[str, ...] = ("fparithvex",)
_FP_SCALAR_VEX_OPERATIONS: tuple[str, ...] = (
    "vaddss",
    "vsubss",
    "vmulss",
    "vdivss",
    "vsqrtss",
    "vminss",
    "vmaxss",
    "vaddsd",
    "vsubsd",
    "vmulsd",
    "vdivsd",
    "vsqrtsd",
    "vminsd",
    "vmaxsd",
)
_FP_PACKED_MEM_KINDS: tuple[str, ...] = (
    "fppload",
    "fppstore",
    "fpploadidx",
    "fppstoreidx",
    "fpploadidxnb",
    "fppstoreidxnb",
    "fpploadrip",
    "fppstorerip",
)
# Micro-op primitives of the virtual operand stack. Reg-reg GP arithmetic lowers to
# a push/push/binop/pop sequence over the vstack rather than one handler computing
# the result, so distinct native ops share the reused push/pop/binop handlers and a
# handler no longer identifies a native instruction. ``vpush``/``vpop`` move a whole
# cell (width-agnostic; keyed at 64); ``v<op>`` pops two cells, folds them (via the
# shared MBA builder) and pushes the result, so it needs the 32/64 width for the
# low-half zero-extension. Their keys reuse the (kind, is_immediate, width) shape.
_MICROOP_STACK_KINDS: tuple[str, ...] = ("vpush", "vpop")
_MICROOP_BINOP_KINDS: tuple[str, ...] = ("vadd", "vsub", "vxor", "vand", "vor")
# ``vpushi`` pushes a width-sized immediate cell (8 bytes at 64, 4 at 32), so unlike
# the width-agnostic ``vpush``/``vpop`` it needs both widths. It lets immediate-form
# arithmetic reuse the same fold/pop primitives as the reg-reg form.
_MICROOP_IMM_KINDS: tuple[str, ...] = ("vpushi",)
_OP_KEYS: tuple[tuple[str, bool, int], ...] = (
    tuple(
        (mnemonic, is_immediate, width)
        for width in (64, 32)
        for mnemonic in _GP_SINGLE_HANDLER_MNEMONICS
        for is_immediate in (True, False)
    )
    + tuple((kind, False, 64) for kind in _MICROOP_STACK_KINDS)
    + tuple((kind, False, width) for width in (64, 32) for kind in _MICROOP_IMM_KINDS)
    + tuple((kind, False, width) for width in (64, 32) for kind in _MICROOP_BINOP_KINDS)
    + tuple((kind, True, width) for width in (64, 32) for kind in _SHIFT_KINDS)
    + tuple((kind, False, width) for width in (64, 32) for kind in _MEM_OP_KINDS)
    + tuple((kind, False, width) for width in (64, 32) for kind in _FP_MEM_KINDS)
    + tuple((kind, False, width) for width in (64, 32) for kind in _FP_ARITH_KINDS)
    + tuple((kind, False, width) for width in (64, 32) for kind in _FP_CONVERT_KINDS)
    + tuple((kind, False, width) for width in (64, 32) for kind in _FP_ARITH_MEM_KINDS)
    + tuple(
        (kind, False, _FP_PACKED_WIDTH)
        for kind in (
            _FP_PACKED_ARITH_KINDS + _FP_PACKED_VEX_ARITH_KINDS + _FP_SCALAR_VEX_ARITH_KINDS + _FP_PACKED_MEM_KINDS
        )
    )
)
_QWORD_BROADCAST = 0x0101010101010101
_DWORD_BROADCAST = 0x01010101

# Reachable, state-neutral junk emitted at each handler instance's entry, so
# duplicate handlers for the same operation diverge in executed code, not just in
# an unreachable tail. It touches only rbx/rbp/r12: every GP register is spilled
# to the frame, the dispatch keeps only rsi/rsp/r15/r13 live, and the straight-
# line VM captures no flags, so these scratch registers and their flag effects are
# dead at a handler's entry.
_LIVE_JUNK_TEMPLATES: tuple[str, ...] = (
    "mov rbx, rbp",
    "xor rbx, r12",
    "and rbp, r12",
    "or r12, rbx",
    "xchg rbx, rbp",
    "add r12, {small}",
    "sub rbx, {small}",
    "lea rbp, [rbp + {small}]",
    "ror r12, {shift}",
    "rol rbx, {shift}",
    "shl rbp, {shift}",
    "add rbx, rbp",
    "sub r12, rbx",
    "not rbp",
    "neg r12",
    "imul rbp, r12, {small}",
    "lea r12, [rbx + rbp]",
    "xchg r12, rbx",
)


# Per-instance opaque-predicate identities. Each computes a value into rbp from a
# scratch seed register ({s}) whose parity is fixed for every input, paired with
# the branch that is consequently always taken. ``x*(x+1)`` / ``x*(x-1)`` (adjacent
# integers) and ``2x`` are always even (jz after test ,1); ``x|1`` and ``x|(x+1)``
# (the latter spans adjacent integers, one of them odd) are always odd (jnz). A
# fixed predicate is itself a signature, so the form is varied per instance.
_OPAQUE_VARIANTS: tuple[tuple[str, str], ...] = (
    ("  lea rbp, [{s} + 1]\n  imul rbp, {s}\n  test rbp, 1\n", "jz"),
    ("  lea rbp, [{s} - 1]\n  imul rbp, {s}\n  test rbp, 1\n", "jz"),
    ("  lea rbp, [{s} + {s}]\n  test rbp, 1\n", "jz"),
    ("  mov rbp, {s}\n  or rbp, 1\n  test rbp, 1\n", "jnz"),
    ("  lea rbp, [{s} + 1]\n  or rbp, {s}\n  test rbp, 1\n", "jnz"),
    # s*s + s == s*(s+1), a product of adjacent integers, always even.
    ("  mov rbp, {s}\n  imul rbp, rbp\n  add rbp, {s}\n  test rbp, 1\n", "jz"),
    # s*s - s == s*(s-1), also adjacent integers, always even.
    ("  mov rbp, {s}\n  imul rbp, rbp\n  sub rbp, {s}\n  test rbp, 1\n", "jz"),
    # 2*s(s+1), an even value doubled, still even.
    ("  lea rbp, [{s} + 1]\n  imul rbp, {s}\n  shl rbp, 1\n  test rbp, 1\n", "jz"),
    # 2*s | 1, an even value with the low bit forced on, always odd.
    ("  lea rbp, [{s} + {s}]\n  or rbp, 1\n  test rbp, 1\n", "jnz"),
    # s | 3, low two bits forced on, always odd.
    ("  mov rbp, {s}\n  and rbp, {s}\n  or rbp, 3\n  test rbp, 1\n", "jnz"),
    # s*s | 1, a square with the low bit forced on, always odd.
    ("  mov rbp, {s}\n  imul rbp, rbp\n  or rbp, 1\n  test rbp, 1\n", "jnz"),
)


def _opaque_predicate_asm(rng: random.Random, index: int) -> str:
    """A reachable, always-taken branch guarding an unreachable junk body.

    One of :data:`_OPAQUE_VARIANTS` (chosen per instance) computes a value whose
    parity is fixed for every input, so its paired branch is always taken and the
    junk body between the branch and the label never executes. The predicate reads
    and writes only rbx/rbp/r12 - state-neutral at a handler head, exactly like the
    live junk above - and clobbers only flags, which the straight-line VM never
    captures, so it adds opaque control flow without touching program state. A
    linear sweep, or a handler signature that assumes straight-line handler heads,
    must now account for a branch whose direction it cannot resolve without proving
    the identity. ``index`` (unique per handler) keeps the skip label unique.
    """
    # Every identity only reads the seed (it writes rbp), so the seed can be a
    # live register the dispatch keeps - the bytecode stream pointer rsi or the
    # position r13 - without clobbering it. Branching on genuine runtime VM state,
    # not dead scratch, defeats the "branch on an unconstrained value -> prune as
    # opaque" heuristic; rbx/r12 (dead scratch here) keep cheaper variants in play.
    seed = rng.choice(("rbx", "r12", "rsi", "r13"))  # rbp holds the predicate accumulator
    compute, branch = rng.choice(_OPAQUE_VARIANTS)
    dead = "".join(
        "  " + rng.choice(_LIVE_JUNK_TEMPLATES).format(small=rng.randint(1, 127), shift=rng.randint(1, 31)) + "\n"
        for _ in range(rng.randint(1, 3))
    )
    return f"{compute.format(s=seed)}  {branch} opaque_{index}\n{dead}opaque_{index}:\n"


def _live_junk_asm(rng: random.Random, index: int) -> str:
    """A short run of reachable, state-neutral junk for the head of a handler,
    sometimes capped with an opaque-predicate branch over an unreachable body."""
    lines = []
    for _ in range(rng.randint(1, 4)):
        template = rng.choice(_LIVE_JUNK_TEMPLATES)
        lines.append("  " + template.format(small=rng.randint(1, 127), shift=rng.randint(1, 31)) + "\n")
    if rng.random() < _LIVE_OPAQUE_PROBABILITY:
        lines.append(_opaque_predicate_asm(rng, index))
    return "".join(lines)


# Private stack frame the interpreter carves below the caller's rsp. The
# 16 GP context slots are scattered across [0x00, 0xA0); the runtime
# self-checksum, xmm save slots and virtual operand stack are packed per build in
# [0xA0, 0x210); the System V red zone [original_rsp-128, original_rsp)
# maps to the top [0x210, 0x290) and is left untouched, so leaf-function red-zone
# data survives. The vstack sits in interpreter-private space below the red zone,
# the same trust class as the xmm save area. The xmm slots are only spilled/reloaded
# when the run contains an FP op (see ``has_fp``); a GP-only run pays the frame but
# not the save/restore.
_FRAME_SIZE = 0x290
_FRAME_SIZES = (0x290, 0x2B0, 0x2D0, 0x2F0)


@dataclass(eq=False, repr=False, slots=True)
class VMScheme:
    """Per-instance randomization of the VM, for polymorphism and opacity.

    Each virtualized run is generated with a fresh scheme: the opcode byte
    assigned to every operation is randomized, and the bytecode stream is
    XOR-encrypted with a per-instance key the interpreter decrypts on the
    fly. Two builds of the same code therefore share neither a fixed opcode
    table nor a readable bytecode blob, so a static signature of one does not
    match another.
    """

    dup: dict[tuple[str, bool, int], tuple[int, ...]]
    exit_opcode: int
    xor_key: int
    slot_perm: tuple[int, ...]
    table_key: int
    junk_seed: int
    field_perm: int = 0
    body_seed: int = 0
    frame_seed: int = 0
    engine_isa_seed: int = 0
    frame_size: int = _FRAME_SIZE
    record_padding: tuple[int, ...] = ()
    immediate_split: bool = False
    checksum_bytewise: bool = False
    checksum_reverse: bool = False


# The opcode is a single byte and the dispatch bounds guard compares ``al``
# against ``total``, so the assigned opcode indices plus at least one exit-marker
# byte (any value ``>= total``) must all fit in ``[0, 256)``. Reserve a small band
# above ``total`` so the exit marker itself stays varied across builds.
# Keep several values above the dense handler range available for the exit
# marker while leaving room for every operation the engine can emit.
# Four values above the dense handler range remain reserved for the randomized
# exit marker while the packed indexed memory forms use the freed opcode slots.
_EXIT_OPCODE_HEADROOM = 4
_OPCODE_BUDGET = 256 - _EXIT_OPCODE_HEADROOM

# Every operation is emitted as several interchangeable handler instances rather
# than one, so no opcode decompiles to a single switch case a devirtualizer can
# name outright; per-instance junk, opaque predicates and (for arithmetic and
# addressing) per-instance MBA folds keep the copies from folding back together.
# Now that the copies diverge semantically and not only in junk, the count is
# pushed higher to widen the visible handler set toward a commercial protector's
# many variants: the floor is well above one and the ceiling large, bounded only
# by the single-byte opcode space (a draw that would overflow the budget is shed
# down to a floor of one, so a large ISA still fits).
_HANDLER_MIN_INSTANCES = 4
_HANDLER_MAX_INSTANCES = 8


def _assign_opcode_multiplicity[OpKey: Hashable](op_keys: Sequence[OpKey], rng: random.Random) -> dict[OpKey, int]:
    """Several interchangeable opcodes per op-key, shed to fit the byte budget.

    Each op-key draws a multiplicity in
    ``[_HANDLER_MIN_INSTANCES, _HANDLER_MAX_INSTANCES]``; if the total would
    exceed the opcode budget, instances are shed (rng-ordered, one at a time,
    never below one) until it fits, so the scheme is always valid however many
    op-keys exist. The shed only draws extra randomness when it triggers, so
    schemes that already fit are unaffected by it.
    """
    if len(op_keys) > _OPCODE_BUDGET:
        raise ValueError(f"{len(op_keys)} op-keys exceed the {_OPCODE_BUDGET}-value single-byte opcode budget")
    multiplicity = {op_key: rng.randint(_HANDLER_MIN_INSTANCES, _HANDLER_MAX_INSTANCES) for op_key in op_keys}
    total = sum(multiplicity.values())
    while total > _OPCODE_BUDGET:
        # len(op_keys) <= _OPCODE_BUDGET is guaranteed above, so once every key is
        # at one the total is within budget and this loop has already exited.
        reducible = [op_key for op_key in op_keys if multiplicity[op_key] > 1]
        rng.shuffle(reducible)
        for op_key in reducible:
            if total <= _OPCODE_BUDGET:
                break
            multiplicity[op_key] -= 1
            total -= 1
    return multiplicity


def build_vm_scheme(rng: random.Random) -> VMScheme:
    """Draw a fresh randomized VM scheme from ``rng`` (seedable, replayable).

    Each operation gets one or two interchangeable opcode indices; the indices
    are a per-instance permutation of the dense range ``0..total-1`` the dispatch
    consumes directly as an offset-table index, while the exit marker is any byte
    ``>= total`` and routes through the bounds guard. Two builds share neither the
    opcode->operation mapping nor the duplication, and the same operation appears
    under several opcodes.
    """
    multiplicity = _assign_opcode_multiplicity(_OP_KEYS, rng)
    total = sum(multiplicity.values())
    indices = rng.sample(range(total), total)
    dup: dict[tuple[str, bool, int], tuple[int, ...]] = {}
    cursor = 0
    for op_key in _OP_KEYS:
        count = multiplicity[op_key]
        dup[op_key] = tuple(indices[cursor : cursor + count])
        cursor += count
    exit_opcode = rng.randrange(total, 256)
    outlier_slots = tuple(range(len(GP_REGISTERS), 0xA0 // 8))
    outlier_count = rng.randint(1, len(outlier_slots))
    selected_slots = rng.sample(range(len(GP_REGISTERS)), len(GP_REGISTERS) - outlier_count)
    selected_slots.extend(rng.sample(outlier_slots, outlier_count))
    slot_perm = tuple(rng.sample(selected_slots, len(selected_slots)))
    xor_key = rng.randrange(1, 256)
    table_key = rng.randrange(1, 1 << 32)
    junk_seed = rng.randrange(1 << 31)
    field_perm = rng.randrange(1, 1 << 31)
    body_seed = rng.randrange(1 << 31)
    frame_seed = rng.randrange(1 << 31)
    # Drawn last so adding the ISA personality does not shift any earlier field's
    # value for a given seed; the other fields stay byte-for-byte stable.
    engine_isa_seed = rng.randrange(1 << 31)
    frame_size = rng.choice(_FRAME_SIZES)
    record_padding = tuple(rng.randrange(3) for _ in range(total))
    immediate_split = bool(rng.randrange(2))
    # Derive the traversal mode without consuming the caller's RNG stream: later
    # handler/junk draws must remain stable when this field is added.
    checksum_bytewise = bool((field_perm ^ xor_key) & 1)
    checksum_reverse = bool((field_perm ^ table_key) & 2)
    return VMScheme(
        dup,
        exit_opcode,
        xor_key,
        slot_perm,
        table_key,
        junk_seed,
        field_perm,
        body_seed,
        frame_seed,
        engine_isa_seed,
        frame_size,
        record_padding,
        immediate_split,
        checksum_bytewise,
        checksum_reverse,
    )


def immediate_fits_width(value: int, width: int) -> bool:
    """Whether ``value`` is representable in ``width`` bits, signed or unsigned.

    Assemblers spell a width-bit immediate either way (e.g. a magic constant
    like ``0x811c9dc5`` is an unsigned 32-bit value that exceeds the signed
    range); both are valid bit patterns the VM can carry, so accept the union.
    """
    return bool(-(2 ** (width - 1)) <= value <= 2**width - 1)


def pack_immediate(value: int, width: int) -> bytes:
    """Pack a width-bit immediate as little-endian, masking to its bit width so
    signed and unsigned values both encode to the same bytes the CPU expects."""
    if width == ARCH_BITS_64:
        return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
    return struct.pack("<I", value & 0xFFFFFFFF)
