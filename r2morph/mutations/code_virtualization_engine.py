"""
Code virtualization engine - real, semantics-preserving register VM.

Transforms a straight-line run of general-purpose register instructions
into bytecode for a small stack-context virtual machine. The native run is
replaced by a trampoline into a generated interpreter that spills the
architectural registers to a private stack frame, executes the bytecode
against that context, reloads the registers, and jumps back to the
instruction following the run.

Correctness contract (why this preserves semantics):

- Only GP-register data/arithmetic ops are virtualized
  (``mov``/``add``/``sub``/``xor``/``and``/``or`` with register or
  immediate operands). Both 64-bit and 32-bit operand widths are modeled;
  32-bit handlers reproduce x86-64 zero-extension (the upper half of the
  destination is cleared). A register-to-register op whose operands disagree
  on width is rejected, not approximated.
- ``rsp`` is never an operand: the interpreter owns the stack pointer
  (restores it verbatim on exit), so a run that modified ``rsp`` could
  not be reproduced and is rejected.
- The interpreter clobbers flags, so a run is only virtualized when the
  caller has proven flags are dead after it.
- Memory, RIP-relative, segment, and control-flow operands end the run;
  the VM only models register transfers.

A run that cannot be proven correct yields ``None`` - the caller leaves
the function untouched. Zero virtualizations always beats a corrupt one.
"""

from __future__ import annotations

import logging
import random
import struct

from r2morph.mutations.code_virtualization_dispatch import decode_block, thread_back_jumps
from r2morph.mutations.code_virtualization_layout import (
    idx_offsets,
    idx_permuted_fields,
    mem_offsets,
    mem_permuted_fields,
    op_offsets,
    op_permuted_fields,
)
from r2morph.mutations.code_virtualization_mba import _mba_add, _mba_add_r10_rax, _op_mba_compute
from r2morph.mutations.code_virtualization_region_integrity import (
    checksum_prologue_asm,
    compute_build_checksum,
)

logger = logging.getLogger(__name__)

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

SUPPORTED_MNEMONICS: frozenset[str] = frozenset({"mov", "add", "sub", "xor", "and", "or"})
_MNEMONIC_ORDER: tuple[str, ...] = ("mov", "add", "sub", "xor", "and", "or")

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
_MEM_BASE_KINDS: tuple[str, ...] = ("load", "store", "lea") + tuple(f"mem{m}" for m in _MEM_ARITH_MNEMONICS)
# movzx/movsx of a byte/word from [base+disp], zero-/sign-extended into the dst.
# (No rip-relative counterpart: the decoder only produces the base+disp form.)
_MEM_MOVX_KINDS: tuple[str, ...] = ("movzxb", "movzxw", "movsxb", "movsxw")
# Indexed [base+index*scale+disp] forms (arrays). lea, arithmetic, and the
# byte/word extends; the handler strips the ``idx`` suffix and reuses the base
# kind's body with the indexed address prologue (a 9-byte item:
# opcode+reg+base+index+scale+disp).
_MEM_IDX_KINDS: tuple[str, ...] = ("lea",) + tuple(f"mem{m}" for m in _MEM_ARITH_MNEMONICS) + _MEM_MOVX_KINDS
_MEM_OP_KINDS: tuple[str, ...] = (
    _MEM_BASE_KINDS
    + tuple(f"{kind}rip" for kind in _MEM_BASE_KINDS)
    + _MEM_MOVX_KINDS
    + tuple(f"{kind}idx" for kind in _MEM_IDX_KINDS)
)
_OP_KEYS: tuple[tuple[str, bool, int], ...] = tuple(
    (mnemonic, is_immediate, width)
    for width in (64, 32)
    for mnemonic in _MNEMONIC_ORDER
    for is_immediate in (True, False)
) + tuple((kind, False, width) for width in (64, 32) for kind in _MEM_OP_KINDS)
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
    seed = rng.choice(("rbx", "r12"))  # rbp holds the predicate accumulator
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
    for _ in range(rng.randint(0, 3)):
        template = rng.choice(_LIVE_JUNK_TEMPLATES)
        lines.append("  " + template.format(small=rng.randint(1, 127), shift=rng.randint(1, 31)) + "\n")
    if rng.random() < 0.5:
        lines.append(_opaque_predicate_asm(rng, index))
    return "".join(lines)


# Private stack frame the interpreter carves below the caller's rsp. The
# 16 context slots occupy [0x00, 0x80); the runtime self-checksum byte sits at
# 0x80; the System V red zone [original_rsp-128, original_rsp) maps to the top
# [0x90, 0x110) and is left untouched, so leaf-function red-zone data survives.
_FRAME_SIZE = 0x110
# Frame byte holding the interpreter's runtime self-checksum (below the red zone).
_CHECKSUM_OFFSET = 0x80


class VMScheme:
    """Per-instance randomization of the VM, for polymorphism and opacity.

    Each virtualized run is generated with a fresh scheme: the opcode byte
    assigned to every operation is randomized, and the bytecode stream is
    XOR-encrypted with a per-instance key the interpreter decrypts on the
    fly. Two builds of the same code therefore share neither a fixed opcode
    table nor a readable bytecode blob, so a static signature of one does not
    match another.
    """

    __slots__ = ("dup", "exit_opcode", "xor_key", "slot_perm", "table_key", "junk_seed", "field_perm")

    def __init__(
        self,
        dup: dict[tuple[str, bool, int], tuple[int, ...]],
        exit_opcode: int,
        xor_key: int,
        slot_perm: tuple[int, ...],
        table_key: int,
        junk_seed: int,
        field_perm: int = 0,
    ) -> None:
        # Each operation gets one or more interchangeable opcode indices; the same
        # operation can appear under different opcodes in the stream and each index
        # emits its own handler instance (with its own junk), so the opcode->
        # operation map is not one-to-one and opcode frequency reveals nothing.
        self.dup = dup
        self.exit_opcode = exit_opcode
        self.xor_key = xor_key
        # Per-instance bijection: logical register index -> shuffled frame slot.
        self.slot_perm = slot_perm
        # Seeds the deterministic per-build choice of opcode-among-duplicates and
        # the per-handler-instance junk that diverges otherwise-identical copies.
        self.junk_seed = junk_seed
        # 32-bit key the dispatch-table offsets are XOR-encrypted with, so the
        # handler addresses are not a plaintext jump table a disassembler recovers
        # as a switch (the dispatch decrypts each entry before jumping).
        self.table_key = table_key
        # Seed for this build's operand field-order permutation: the encoder and
        # the handlers derive each item's field offsets from it (via the shared
        # layout module), so the operand layout differs per build. 0 is identity.
        self.field_perm = field_perm


def build_vm_scheme(rng: random.Random) -> VMScheme:
    """Draw a fresh randomized VM scheme from ``rng`` (seedable, replayable).

    Each operation gets one or two interchangeable opcode indices; the indices
    are a per-instance permutation of the dense range ``0..total-1`` that index
    the dispatch table directly (so there is no comparison ladder), while the
    exit marker is any byte ``>= total`` and routes through the table's bounds
    guard. Two builds share neither the opcode->operation mapping nor the
    duplication, and the same operation appears under several opcodes.
    """
    multiplicity = {op_key: rng.randint(1, 2) for op_key in _OP_KEYS}
    total = sum(multiplicity.values())
    indices = rng.sample(range(total), total)
    dup: dict[tuple[str, bool, int], tuple[int, ...]] = {}
    cursor = 0
    for op_key in _OP_KEYS:
        count = multiplicity[op_key]
        dup[op_key] = tuple(indices[cursor : cursor + count])
        cursor += count
    exit_opcode = rng.randrange(total, 256)
    slot_perm = tuple(rng.sample(range(len(GP_REGISTERS)), len(GP_REGISTERS)))
    return VMScheme(
        dup,
        exit_opcode,
        rng.randrange(1, 256),
        slot_perm,
        rng.randrange(1, 1 << 32),
        rng.randrange(1 << 31),
        rng.randrange(1, 1 << 31),
    )


class VirtualizedOp:
    """A single decoded instruction destined for the VM bytecode."""

    __slots__ = ("mnemonic", "dst_index", "value", "is_immediate", "width")

    def __init__(self, mnemonic: str, dst_index: int, value: int, is_immediate: bool, width: int) -> None:
        self.mnemonic = mnemonic
        self.dst_index = dst_index
        self.value = value
        self.is_immediate = is_immediate
        self.width = width


class VirtualizedMemOp:
    """A ``mov`` between a register slot and ``[base+disp]`` memory.

    ``kind`` is ``"load"`` (reg <- [base+disp]) or ``"store"`` ([base+disp] <-
    reg). The base value is read from its spilled frame slot at runtime, so the
    address is the program's real address (the interpreter does not relocate the
    stack - it only spills registers), and a 32-bit load zero-extends.
    """

    __slots__ = ("kind", "reg_index", "base_index", "disp", "width", "index_index", "scale")

    def __init__(
        self, kind: str, reg_index: int, base_index: int, disp: int, width: int, index_index: int = 0, scale: int = 0
    ) -> None:
        self.kind = kind
        self.reg_index = reg_index
        self.base_index = base_index
        self.disp = disp
        self.width = width
        # Only used by the ``*idx`` kinds: address = base + index*(2**scale) + disp.
        self.index_index = index_index
        self.scale = scale


# Mean junk ops inserted per real op. ``mov reg, reg`` is a perfect identity (a
# slot written with its own value, no flags), so it is semantics-preserving for
# any register, yet it executes a real handler and pads the bytecode with
# operations a devirtualizer cannot distinguish from the program's. The run is
# straight-line (no branches), so insertion needs no target remap. Kept modest so
# the per-run execution cost stays bounded. Mirrors the region lifter's tuning.
_JUNK_OP_PROBABILITY = 0.35


def inject_junk_ops(
    ops: list[VirtualizedOp | VirtualizedMemOp], rng: random.Random
) -> list[VirtualizedOp | VirtualizedMemOp]:
    """Sprinkle identity ``mov reg, reg`` ops through a straight-line run."""
    junk_regs = [index for index in range(len(GP_REGISTERS)) if index != RSP_INDEX]
    out: list[VirtualizedOp | VirtualizedMemOp] = []
    for op in ops:
        while rng.random() < _JUNK_OP_PROBABILITY:
            reg = rng.choice(junk_regs)
            out.append(VirtualizedOp("mov", reg, reg, False, 64))
        out.append(op)
    return out


def _normalize_operand(token: str) -> str:
    return token.strip().lower()


def _parse_immediate(token: str) -> int | None:
    token = token.strip()
    try:
        return int(token, 0)
    except ValueError:
        return None


def _register_slot(name: str) -> tuple[int, int] | None:
    """Return (slot, width) for a 64- or 32-bit GP register, else None.

    The stack pointer is excluded in both widths: the interpreter owns rsp.
    """
    if name in REGISTER_INDEX:
        return (REGISTER_INDEX[name], 64) if name != "rsp" else None
    if name in REGISTER32_INDEX:
        return (REGISTER32_INDEX[name], 32) if name != "esp" else None
    return None


def decode_instruction(disasm: str) -> VirtualizedOp | None:
    """
    Decode one disassembled instruction into a :class:`VirtualizedOp`.

    Returns ``None`` for anything the VM cannot reproduce exactly: a
    non-supported mnemonic, a non-GP register, a memory/RIP/segment operand,
    any stack-pointer involvement, or a register-to-register op whose operands
    disagree on width.
    """
    text = disasm.strip()
    if " " not in text:
        return None

    mnemonic, operand_text = text.split(None, 1)
    mnemonic = mnemonic.lower()
    # ``movabs`` is the disassembler's spelling of a ``mov`` with a 64-bit
    # immediate (or an absolute moffs, which the memory-operand guard below
    # rejects); treat it as a plain ``mov`` so 64-bit constants virtualize.
    if mnemonic == "movabs":
        mnemonic = "mov"
    if mnemonic not in SUPPORTED_MNEMONICS:
        return None

    if "," not in operand_text:
        return None
    dst_token, src_token = operand_text.split(",", 1)
    dst = _register_slot(_normalize_operand(dst_token))
    src_name = _normalize_operand(src_token)
    if dst is None:
        return None
    dst_slot, width = dst

    src = _register_slot(src_name)
    if src is not None:
        src_slot, src_width = src
        if src_width != width:
            return None
        return VirtualizedOp(mnemonic, dst_slot, src_slot, is_immediate=False, width=width)

    # Reject memory/RIP/segment operands - anything that is not a bare GP
    # register or a plain immediate.
    if any(marker in src_name for marker in ("[", "]", "rip", ":", "ptr")):
        return None

    immediate = _parse_immediate(src_name)
    if immediate is None or not immediate_fits_width(immediate, width):
        return None
    return VirtualizedOp(mnemonic, dst_slot, immediate, is_immediate=True, width=width)


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
    if width == 64:
        return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
    return struct.pack("<I", value & 0xFFFFFFFF)


def encode_bytecode(
    ops: list[VirtualizedOp | VirtualizedMemOp], scheme: VMScheme, checksum: int = 0, bytecode_base: int = 0
) -> bytes:
    """Serialize ops to bytecode (per-scheme opcodes), XOR-encrypted by key.

    Immediates are width-sized: 8 bytes for 64-bit ops, 4 for 32-bit.

    ``checksum`` is the expected runtime self-checksum of the interpreter, XORed
    into every opcode so the dispatch (which re-derives it) cancels it on a
    faithful build and misdecodes if the interpreter is patched.
    """
    slot_of = scheme.slot_perm  # logical register index -> shuffled frame slot
    pick = random.Random(scheme.junk_seed).choice  # deterministic per build
    plain = bytearray()

    def emit_opcode(opcode: int) -> int:
        # Mask the opcode byte with its own stream position (the dispatcher
        # subtracts it back out) so the same operation does not encode to the
        # same byte twice and a single-byte XOR of the blob cannot expose the
        # opcode stream. The exit marker is masked the same way and still decodes
        # to a value >= N, so it leaves through the dispatcher's bounds guard.
        # The position is reused to mask this item's operands so they are not all
        # decrypted by one constant key byte a handler trivially reveals.
        position = len(plain) & 0xFF
        plain.append(opcode ^ position ^ checksum)
        return position

    fp = scheme.field_perm

    def emit_fields(position: int, order: list[tuple[str, int]], field_bytes: dict[str, bytes]) -> None:
        # Emit the item's operand fields in this build's permuted order; the
        # handler reads them at the matching offsets via the same layout helper.
        for name, _size in order:
            plain.extend(byte ^ position for byte in field_bytes[name])

    for op in ops:
        if isinstance(op, VirtualizedMemOp):
            position = emit_opcode(pick(scheme.dup[(op.kind, False, op.width)]))
            if op.kind.endswith("rip"):
                # No base slot; the disp field carries the absolute global target,
                # stored as a signed offset from the bytecode base (out-of-range
                # raises struct.error, which the caller turns into "leave native").
                field_bytes = {
                    "reg": bytes([slot_of[op.reg_index]]),
                    "disp": struct.pack("<i", op.disp - bytecode_base),
                }
                emit_fields(position, mem_permuted_fields(True, fp), field_bytes)
            elif op.kind.endswith("idx"):
                field_bytes = {
                    "reg": bytes([slot_of[op.reg_index]]),
                    "base": bytes([slot_of[op.base_index]]),
                    "index": bytes([slot_of[op.index_index]]),
                    "shift": bytes([op.scale]),
                    "disp": struct.pack("<i", op.disp),
                }
                emit_fields(position, idx_permuted_fields(False, fp), field_bytes)
            else:
                field_bytes = {
                    "reg": bytes([slot_of[op.reg_index]]),
                    "base": bytes([slot_of[op.base_index]]),
                    "disp": struct.pack("<i", op.disp),
                }
                emit_fields(position, mem_permuted_fields(False, fp), field_bytes)
            continue
        position = emit_opcode(pick(scheme.dup[(op.mnemonic, op.is_immediate, op.width)]))
        if op.is_immediate:
            field_bytes = {"dst": bytes([slot_of[op.dst_index]]), "imm": pack_immediate(op.value, op.width)}
        else:
            field_bytes = {"dst": bytes([slot_of[op.dst_index]]), "src": bytes([slot_of[op.value]])}
        emit_fields(position, op_permuted_fields(op.is_immediate, op.width, fp), field_bytes)
    emit_opcode(scheme.exit_opcode)  # no operands
    key = scheme.xor_key
    return bytes(byte ^ key for byte in plain)


def _interpreter_asm(continuation_vaddr: int, scheme: VMScheme) -> str:
    """Generate the interpreter assembly for one virtualized run.

    Every byte fetched from the bytecode is XOR-decrypted with the scheme key
    before use; opcodes are compared against the scheme's randomized values.
    """
    key = scheme.xor_key
    key_qword = hex((key * _QWORD_BROADCAST) & 0xFFFFFFFFFFFFFFFF)
    key_dword = hex((key * _DWORD_BROADCAST) & 0xFFFFFFFF)
    # Each opcode index gets its own handler instance; an operation with two
    # indices is emitted twice, each copy carrying different junk, so the
    # opcode->operation map is not one-to-one and the duplicates share no byte
    # signature. ``total`` is the dispatch-table width and the bounds-guard limit.
    index_to_key = {index: op_key for op_key, indices in scheme.dup.items() for index in indices}
    total = len(index_to_key)
    junk_rng = random.Random(scheme.junk_seed)

    def mem_addr_prologue() -> str:
        # Shared head of every memory handler: reg slot [rsi+1] -> r8, base slot
        # [rsi+2] -> r9, signed disp32 [rsi+3..6] -> rax. Each operand is un-masked
        # by key XOR r13b (the stream position); the disp broadcasts r13b to 32 bits
        # before sign-extending. The effective address is the base slot's current
        # value plus the displacement, folded with the shared MBA add (no literal
        # address add), left in r10.
        off = mem_offsets(False, scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
            f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            "  movsxd rax, eax\n  mov r10, qword ptr [rsp + r9*8]\n" + _mba_add_r10_rax(key)
        )

    def mem_riprel_prologue() -> str:
        # rip-relative head: reg slot [rsi+1] -> r8, signed offset32 [rsi+2..5] (the
        # global's distance from the bytecode base). The address is r15 (the bytecode
        # base, held for the whole run) plus that offset, folded with MBA; so the
        # global is reached base-independently exactly like the original [rip+disp].
        off = mem_offsets(True, scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
            f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            "  movsxd rax, eax\n  mov r10, r15\n" + _mba_add_r10_rax(key)
        )

    def mem_idx_prologue() -> str:
        # Indexed head: reg [rsi+1]->r8, base [rsi+2]->r9, index [rsi+3]->r11,
        # scale-shift [rsi+4]->cl, signed disp32 [rsi+5..8]. Computes
        # base + index*(2**scale) + disp into r10, both adds folded with MBA.
        off = idx_offsets(False, scheme.field_perm)
        return (
            f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
            f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            f"  movzx r11d, byte ptr [rsi+{off['index']}]\n  xor r11b, {key}\n  xor r11b, r13b\n"
            f"  movzx ecx, byte ptr [rsi+{off['shift']}]\n  xor cl, {key}\n  xor cl, r13b\n"
            f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r10d, {key_dword}\n  xor eax, r10d\n"
            f"  movzx r10d, r13b\n  imul r10d, r10d, {hex(_DWORD_BROADCAST)}\n  xor eax, r10d\n"
            "  movsxd rax, eax\n  mov r10, qword ptr [rsp + r11*8]\n  shl r10, cl\n"
            "  mov r11, qword ptr [rsp + r9*8]\n" + _mba_add("r11", "rcx", key) + _mba_add("rax", "rcx", key)
        )

    def mem_handler_body(kind: str, width: int) -> str:
        # base+disp items are 7 bytes (opcode+reg+base+disp32); rip-relative items
        # are 6 (opcode+reg+offset32); indexed items are 9 (opcode+reg+base+index+
        # scale+disp32). r10 holds the address in every case.
        if kind.endswith("rip"):
            kind, body, advance = kind[: -len("rip")], mem_riprel_prologue(), 6
        elif kind.endswith("idx"):
            kind, body, advance = kind[: -len("idx")], mem_idx_prologue(), 9
        else:
            body, advance = mem_addr_prologue(), 7
        if kind == "load":
            body += "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
            body += "  mov qword ptr [rsp + r8*8], rax\n"
        elif kind == "store":
            if width == 64:
                body += "  mov rax, qword ptr [rsp + r8*8]\n  mov qword ptr [r10], rax\n"
            else:
                body += "  mov eax, dword ptr [rsp + r8*8]\n  mov dword ptr [r10], eax\n"
        elif kind == "lea":
            # Store the effective address itself (no dereference). A 32-bit dst
            # truncates to the low 32 bits, zero-extended into the slot.
            if width == 32:
                body += "  mov r10d, r10d\n"
            body += "  mov qword ptr [rsp + r8*8], r10\n"
        elif kind.startswith(("movzx", "movsx")):
            # Zero/sign-extend a byte or word from [addr] into the destination slot.
            # movzx always zero-extends the same regardless of dst width; movsx's
            # target register depends on whether the destination is 32- or 64-bit.
            size_word = "byte" if kind.endswith("b") else "word"
            if kind.startswith("movzx"):
                body += f"  movzx eax, {size_word} ptr [r10]\n"
            elif width == 64:
                body += f"  movsx rax, {size_word} ptr [r10]\n"
            else:
                body += f"  movsx eax, {size_word} ptr [r10]\n"
            body += "  mov qword ptr [rsp + r8*8], rax\n"
        else:
            # mem<op>: reg = reg <op> [addr], computed with no literal native op via
            # the shared MBA builder (flags dead by the engine's precondition). Load
            # the memory source into rax, the register into r10, then fold.
            mnemonic = kind[len("mem") :]
            body += "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
            if mnemonic == "sub":
                body += "  neg rax\n"
            body += "  mov r10, qword ptr [rsp + r8*8]\n" if width == 64 else "  mov r10d, dword ptr [rsp + r8*8]\n"
            body += _op_mba_compute(mnemonic, key)
            if width == 64:
                body += "  mov qword ptr [rsp + r8*8], r10\n"
            else:
                body += "  mov r10d, r10d\n  mov qword ptr [rsp + r8*8], r10\n"
        return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"

    def handler_body(mnemonic: str, is_immediate: bool, width: int) -> str:
        if mnemonic in _MEM_OP_KINDS:
            return mem_handler_body(mnemonic, width)
        # Operands carry the opcode's stream position too (r13 still holds it from
        # the dispatch), so each is un-masked by both the key and r13b - there is
        # no lone constant-key decrypt repeated across every handler.
        off = op_offsets(is_immediate, width, scheme.field_perm)
        decrypt_dst = f"  movzx r8d, byte ptr [rsi+{off['dst']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        if is_immediate and width == 64:
            load = (
                f"  mov rax, qword ptr [rsi+{off['imm']}]\n  mov r10, {key_qword}\n  xor rax, r10\n"
                f"  movzx r10, r13b\n  mov r11, {hex(_QWORD_BROADCAST)}\n  imul r10, r11\n  xor rax, r10\n"
            )
            advance = "  add rsi, 10\n"
        elif is_immediate:
            load = (
                f"  mov eax, dword ptr [rsi+{off['imm']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
                f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            )
            advance = "  add rsi, 6\n"
        else:
            load = f"  movzx r9d, byte ptr [rsi+{off['src']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            load += "  mov rax, qword ptr [rsp + r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp + r9*8]\n"
            advance = "  add rsi, 3\n"

        # rax/eax now holds the source value (immediate or register). mov stores it
        # verbatim; the arithmetic/boolean ops compute the result with no literal
        # native op via the shared MBA builder, so the handler never spells out the
        # operation it performs. The MBA is unconditional here because a run is only
        # virtualized when its flags are dead afterward (the engine's precondition),
        # so clobbering flags is always safe - no flag-liveness analysis needed. A
        # 32-bit op writes the low half and zero-extends, matching x86-64.
        if mnemonic == "mov":
            apply = "  mov qword ptr [rsp + r8*8], rax\n"
        else:
            # sub a, b == add a, (-b): negate the source, then the same MBA add fold.
            apply = "  neg rax\n" if mnemonic == "sub" else ""
            apply += "  mov r10, qword ptr [rsp + r8*8]\n" if width == 64 else "  mov r10d, dword ptr [rsp + r8*8]\n"
            apply += _op_mba_compute(mnemonic, key)
            if width == 64:
                apply += "  mov qword ptr [rsp + r8*8], r10\n"
            else:
                apply += "  mov r10d, r10d\n  mov qword ptr [rsp + r8*8], r10\n"
        return decrypt_dst + load + apply + advance + "  jmp vm_dispatch\n"

    slot = scheme.slot_perm  # logical register index -> shuffled frame slot
    lines = [f"vm_entry:\n  sub rsp, {_FRAME_SIZE}\n"]
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov qword ptr [rsp + {slot[index] * 8}], {name}\n")
    # Anti-tamper: checksum the interpreter's own code into a frame slot the
    # dispatch folds into every opcode decrypt; runs after the register spill.
    lines.append(checksum_prologue_asm(key, slot=_CHECKSUM_OFFSET))
    # Direct-threaded, polymorphic dispatch: instead of a single shared dispatch
    # block every handler jumps back to (a fan-in hub a devirtualizer flags as the
    # dispatcher by in-degree, and pattern-matches as one fixed sequence), the
    # opcode decode is inlined at the entry and at the tail of every handler, and
    # each copy shuffles its order-independent XOR groups so no two share a byte
    # layout. Each handler decodes the next opcode itself and jumps straight to the
    # next handler - no central dispatcher node. The decode runs once per opcode
    # either way and shuffling only reorders instructions, so executed count and
    # size are unchanged; only the interpreter code grows (one copy per handler).
    poly_rng = random.Random(scheme.table_key)

    def make_decode() -> str:
        return decode_block(
            # Undo the opcode byte's position mask and fold in the key and the
            # runtime self-checksum the encoder pre-biased the opcode with, so a
            # patched interpreter misdecodes.
            opcode_xors=[
                f"  xor al, {key}\n",
                "  xor al, r13b\n",
                f"  xor al, byte ptr [rsp + {_CHECKSUM_OFFSET}]\n",
            ],
            bounds=f"  cmp al, {total}\n  jae vm_exit\n",
            # The stored offsets are XOR-encrypted (not a plaintext switch) and the
            # table key is diffused with the self-checksum (broadcast to 32 bits),
            # so tampering corrupts handler resolution, not just opcodes.
            table_load="  lea r14, [rip + vm_table]\n  mov eax, dword ptr [r14 + rax*4]\n",
            table_xors=[
                f"  xor eax, {hex(scheme.table_key)}\n",
                f"  movzx ecx, byte ptr [rsp + {_CHECKSUM_OFFSET}]\n  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n",
            ],
            rng=poly_rng,
        )

    lines.append(
        f"  lea rax, [rsp + {_FRAME_SIZE}]\n"
        f"  mov qword ptr [rsp + {slot[RSP_INDEX] * 8}], rax\n"
        # r15 holds the bytecode base; r13/r14 are free scratch between handlers.
        "  lea rsi, [rip + bytecode]\n  mov r15, rsi\n" + make_decode()
    )

    for index in range(total):
        mnemonic, is_immediate, width = index_to_key[index]
        # Reachable head junk makes duplicate handlers diverge in executed code.
        lines.append(f"h_{index}:\n{_live_junk_asm(junk_rng, index)}{handler_body(mnemonic, is_immediate, width)}")

    lines.append("vm_exit:\n")
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov {name}, qword ptr [rsp + {slot[index] * 8}]\n")
    lines.append(f"  add rsp, {_FRAME_SIZE}\n  jmp {hex(continuation_vaddr)}\n")

    table = "".join(f"  .long h_{index} - vm_table\n" for index in range(total))
    lines.append(f"vm_table:\n{table}bytecode:\n")
    # Thread the dispatch: every handler tail ends with a back jump to the (now
    # removed) central dispatcher; splice a freshly shuffled decode copy in for each
    # so control flows handler -> decode -> next handler with no shared hub block
    # and no two copies sharing a byte layout.
    return thread_back_jumps("".join(lines), make_decode)


def build_vm_blob(
    ops: list[VirtualizedOp | VirtualizedMemOp], cave_vaddr: int, continuation_vaddr: int, scheme: VMScheme
) -> bytes | None:
    """
    Assemble the interpreter at ``cave_vaddr`` and append the encrypted bytecode.

    The interpreter's ``lea rsi, [rip + bytecode]`` resolves to the byte
    immediately after the assembled code, where the bytecode is appended.
    Returns ``None`` if keystone is unavailable or assembly fails - the
    caller then leaves the function untouched.
    """
    try:
        import keystone
    except ImportError:
        logger.warning("keystone unavailable; cannot virtualize")
        return None

    asm = _interpreter_asm(continuation_vaddr, scheme)
    try:
        engine = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, _ = engine.asm(asm, cave_vaddr)
    except keystone.KsError as exc:
        logger.debug("VM interpreter assembly failed: %s", exc)
        return None
    if not encoding:
        logger.debug("VM interpreter assembly produced no bytes")
        return None

    # The dispatch table is the tail len(_OP_KEYS) 32-bit entries of the assembled
    # interpreter; XOR-encrypt each in place so the handler addresses are not a
    # plaintext jump table (the dispatch decrypts them at runtime; keystone cannot
    # XOR a label difference it computes itself).
    data = bytearray(encoding)
    total = sum(len(indices) for indices in scheme.dup.values())
    table_start = len(data) - total * 4
    # Expected runtime self-checksum over the interpreter code (everything up to
    # the table, so the encryption below does not perturb it); the encoder folds it
    # into the opcodes, and the table key is diffused with it too.
    checksum = compute_build_checksum(bytes(data[:table_start]), scheme.xor_key)
    table_key = scheme.table_key ^ (checksum * 0x01010101)
    for entry_index in range(total):
        offset = table_start + entry_index * 4
        encrypted = int.from_bytes(data[offset : offset + 4], "little") ^ table_key
        data[offset : offset + 4] = encrypted.to_bytes(4, "little")
    # The bytecode is appended right after the interpreter, so its base is the cave
    # plus the assembled interpreter length; rip-relative globals are stored as a
    # signed 32-bit offset from it. A target too far to express leaves the run native.
    bytecode_base = cave_vaddr + len(data)
    try:
        bytecode = encode_bytecode(ops, scheme, checksum, bytecode_base)
    except struct.error:
        logger.debug("rip-relative target out of 32-bit range; leaving run native")
        return None
    return bytes(data) + bytecode
