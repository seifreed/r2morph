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
_OP_KEYS: tuple[tuple[str, bool, int], ...] = tuple(
    (mnemonic, is_immediate, width)
    for width in (64, 32)
    for mnemonic in _MNEMONIC_ORDER
    for is_immediate in (True, False)
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
)


def _live_junk_asm(rng: random.Random) -> str:
    """A short run of reachable, state-neutral junk for the head of a handler."""
    lines = []
    for _ in range(rng.randint(0, 3)):
        template = rng.choice(_LIVE_JUNK_TEMPLATES)
        lines.append("  " + template.format(small=rng.randint(1, 127), shift=rng.randint(1, 31)) + "\n")
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

    __slots__ = ("dup", "exit_opcode", "xor_key", "slot_perm", "table_key", "junk_seed")

    def __init__(
        self,
        dup: dict[tuple[str, bool, int], tuple[int, ...]],
        exit_opcode: int,
        xor_key: int,
        slot_perm: tuple[int, ...],
        table_key: int,
        junk_seed: int,
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
        dup, exit_opcode, rng.randrange(1, 256), slot_perm, rng.randrange(1, 1 << 32), rng.randrange(1 << 31)
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


def encode_bytecode(ops: list[VirtualizedOp], scheme: VMScheme, checksum: int = 0) -> bytes:
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

    for op in ops:
        position = emit_opcode(pick(scheme.dup[(op.mnemonic, op.is_immediate, op.width)]))
        plain.append(slot_of[op.dst_index] ^ position)
        if op.is_immediate:
            plain += bytes(byte ^ position for byte in pack_immediate(op.value, op.width))
        else:
            plain.append(slot_of[op.value] ^ position)
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

    def handler_body(mnemonic: str, is_immediate: bool, width: int) -> str:
        # Operands carry the opcode's stream position too (r13 still holds it from
        # the dispatch), so each is un-masked by both the key and r13b - there is
        # no lone constant-key decrypt repeated across every handler.
        decrypt_dst = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        if is_immediate and width == 64:
            load = (
                f"  mov rax, qword ptr [rsi+2]\n  mov r10, {key_qword}\n  xor rax, r10\n"
                f"  movzx r10, r13b\n  mov r11, {hex(_QWORD_BROADCAST)}\n  imul r10, r11\n  xor rax, r10\n"
            )
            advance = "  add rsi, 10\n"
        elif is_immediate:
            load = (
                f"  mov eax, dword ptr [rsi+2]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
                f"  movzx r11d, r13b\n  imul r11d, r11d, {hex(_DWORD_BROADCAST)}\n  xor eax, r11d\n"
            )
            advance = "  add rsi, 6\n"
        else:
            load = f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n  xor r9b, r13b\n"
            load += "  mov rax, qword ptr [rsp + r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp + r9*8]\n"
            advance = "  add rsi, 3\n"

        # rax/eax now holds the source value (immediate or register). Apply the
        # operation against the destination slot. A 32-bit op writes the low
        # half and zero-extends, matching x86-64 register semantics.
        if width == 64:
            if mnemonic == "mov":
                apply = "  mov qword ptr [rsp + r8*8], rax\n"
            else:
                apply = f"  {mnemonic} qword ptr [rsp + r8*8], rax\n"
        else:
            if mnemonic == "mov":
                apply = "  mov qword ptr [rsp + r8*8], rax\n"
            else:
                apply = (
                    "  mov r11d, dword ptr [rsp + r8*8]\n"
                    f"  {mnemonic} r11d, eax\n"
                    "  mov qword ptr [rsp + r8*8], r11\n"
                )
        return decrypt_dst + load + apply + advance + "  jmp vm_dispatch\n"

    slot = scheme.slot_perm  # logical register index -> shuffled frame slot
    lines = [f"vm_entry:\n  sub rsp, {_FRAME_SIZE}\n"]
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov qword ptr [rsp + {slot[index] * 8}], {name}\n")
    # Anti-tamper: checksum the interpreter's own code into a frame slot the
    # dispatch folds into every opcode decrypt; runs after the register spill.
    lines.append(checksum_prologue_asm(key, slot=_CHECKSUM_OFFSET))
    lines.append(
        f"  lea rax, [rsp + {_FRAME_SIZE}]\n"
        f"  mov qword ptr [rsp + {slot[RSP_INDEX] * 8}], rax\n"
        "  lea rsi, [rip + bytecode]\n  mov r15, rsi\n"
        # Indirect, opcode-indexed dispatch: the decrypted opcode byte indexes a
        # base-independent offset table (each entry a 32-bit signed offset from
        # vm_table to its handler), so there is no comparison ladder to match and
        # the jump survives rebasing/ASLR like the rest of the blob's rel32 jumps.
        # An opcode >= N (the exit marker) leaves through the bounds guard. r15
        # holds the bytecode base; r13/r14 are free scratch between handlers.
        "vm_dispatch:\n"
        # Undo the opcode byte's position mask (encoder XORed it with rsi-base).
        "  mov r13, rsi\n  sub r13, r15\n"
        "  movzx eax, byte ptr [rsi]\n"
        # Fold in the position mask (r13b) and the runtime self-checksum the
        # encoder pre-biased the opcode with, so a patched interpreter misdecodes.
        f"  xor al, {key}\n  xor al, r13b\n  xor al, byte ptr [rsp + {_CHECKSUM_OFFSET}]\n"
        f"  cmp al, {total}\n  jae vm_exit\n"
        # The stored offsets are XOR-encrypted, so the table is not a plaintext
        # handler map a disassembler can recover as a switch; decrypt each entry.
        # The table key is also diffused with the runtime self-checksum (broadcast
        # to 32 bits), so tampering corrupts handler resolution, not just opcodes.
        f"  lea r14, [rip + vm_table]\n  mov eax, dword ptr [r14 + rax*4]\n  xor eax, {hex(scheme.table_key)}\n"
        f"  movzx ecx, byte ptr [rsp + {_CHECKSUM_OFFSET}]\n  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n"
        "  movsxd rax, eax\n  add rax, r14\n  jmp rax\n"
    )

    for index in range(total):
        mnemonic, is_immediate, width = index_to_key[index]
        # Reachable head junk makes duplicate handlers diverge in executed code.
        lines.append(f"h_{index}:\n{_live_junk_asm(junk_rng)}{handler_body(mnemonic, is_immediate, width)}")

    lines.append("vm_exit:\n")
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov {name}, qword ptr [rsp + {slot[index] * 8}]\n")
    lines.append(f"  add rsp, {_FRAME_SIZE}\n  jmp {hex(continuation_vaddr)}\n")

    table = "".join(f"  .long h_{index} - vm_table\n" for index in range(total))
    lines.append(f"vm_table:\n{table}bytecode:\n")
    return "".join(lines)


def build_vm_blob(ops: list[VirtualizedOp], cave_vaddr: int, continuation_vaddr: int, scheme: VMScheme) -> bytes | None:
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
    return bytes(data) + encode_bytecode(ops, scheme, checksum)
