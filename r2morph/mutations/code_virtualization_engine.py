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

# Private stack frame the interpreter carves below the caller's rsp. The
# 16 context slots occupy [0x00, 0x80); the System V red zone
# [original_rsp-128, original_rsp) maps to [0x80, 0x100) and is left
# untouched, so leaf-function red-zone data survives the detour.
_FRAME_SIZE = 0x100


class VMScheme:
    """Per-instance randomization of the VM, for polymorphism and opacity.

    Each virtualized run is generated with a fresh scheme: the opcode byte
    assigned to every operation is randomized, and the bytecode stream is
    XOR-encrypted with a per-instance key the interpreter decrypts on the
    fly. Two builds of the same code therefore share neither a fixed opcode
    table nor a readable bytecode blob, so a static signature of one does not
    match another.
    """

    __slots__ = ("opcode_values", "exit_opcode", "xor_key", "slot_perm")

    def __init__(
        self,
        opcode_values: dict[tuple[str, bool, int], int],
        exit_opcode: int,
        xor_key: int,
        slot_perm: tuple[int, ...],
    ) -> None:
        self.opcode_values = opcode_values
        self.exit_opcode = exit_opcode
        self.xor_key = xor_key
        # Per-instance bijection: logical register index -> shuffled frame slot.
        self.slot_perm = slot_perm


def build_vm_scheme(rng: random.Random) -> VMScheme:
    """Draw a fresh randomized VM scheme from ``rng`` (seedable, replayable).

    Opcodes are a per-instance permutation of dense indices ``0..N-1`` that
    index the dispatch table directly (so there is no comparison ladder), while
    the exit marker is any byte ``>= N`` and routes through the table's bounds
    guard. Two builds still share no opcode-to-operation mapping.
    """
    indices = rng.sample(range(len(_OP_KEYS)), len(_OP_KEYS))
    opcode_values = dict(zip(_OP_KEYS, indices, strict=True))
    exit_opcode = rng.randrange(len(_OP_KEYS), 256)
    slot_perm = tuple(rng.sample(range(len(GP_REGISTERS)), len(GP_REGISTERS)))
    return VMScheme(opcode_values, exit_opcode, rng.randrange(1, 256), slot_perm)


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


def encode_bytecode(ops: list[VirtualizedOp], scheme: VMScheme) -> bytes:
    """Serialize ops to bytecode (per-scheme opcodes), XOR-encrypted by key.

    Immediates are width-sized: 8 bytes for 64-bit ops, 4 for 32-bit.
    """
    slot_of = scheme.slot_perm  # logical register index -> shuffled frame slot
    plain = bytearray()

    def emit_opcode(opcode: int) -> None:
        # Mask the opcode byte with its own stream position (the dispatcher
        # subtracts it back out) so the same operation does not encode to the
        # same byte twice and a single-byte XOR of the blob cannot expose the
        # opcode stream. The exit marker is masked the same way and still decodes
        # to a value >= N, so it leaves through the dispatcher's bounds guard.
        plain.append(opcode ^ (len(plain) & 0xFF))

    for op in ops:
        emit_opcode(scheme.opcode_values[(op.mnemonic, op.is_immediate, op.width)])
        plain.append(slot_of[op.dst_index])
        if op.is_immediate:
            plain += pack_immediate(op.value, op.width)
        else:
            plain.append(slot_of[op.value])
    emit_opcode(scheme.exit_opcode)
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

    def handler_body(mnemonic: str, is_immediate: bool, width: int) -> str:
        decrypt_dst = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
        if is_immediate and width == 64:
            load = f"  mov rax, qword ptr [rsi+2]\n  mov r10, {key_qword}\n  xor rax, r10\n"
            advance = "  add rsi, 10\n"
        elif is_immediate:
            load = f"  mov eax, dword ptr [rsi+2]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
            advance = "  add rsi, 6\n"
        else:
            load = f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
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
        f"  xor al, {key}\n  xor al, r13b\n"
        f"  cmp al, {len(_OP_KEYS)}\n  jae vm_exit\n"
        "  lea r14, [rip + vm_table]\n  movsxd rax, dword ptr [r14 + rax*4]\n  add rax, r14\n  jmp rax\n"
    )

    def label_for(op_key: tuple[str, bool, int]) -> str:
        mnemonic, is_immediate, width = op_key
        return f"h_{mnemonic}_{'ri' if is_immediate else 'rr'}_{width}"

    for op_key in _OP_KEYS:
        mnemonic, is_immediate, width = op_key
        lines.append(f"{label_for(op_key)}:\n{handler_body(mnemonic, is_immediate, width)}")

    lines.append("vm_exit:\n")
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov {name}, qword ptr [rsp + {slot[index] * 8}]\n")
    lines.append(f"  add rsp, {_FRAME_SIZE}\n  jmp {hex(continuation_vaddr)}\n")

    index_to_label = {scheme.opcode_values[op_key]: label_for(op_key) for op_key in _OP_KEYS}
    table = "".join(f"  .long {index_to_label[index]} - vm_table\n" for index in range(len(_OP_KEYS)))
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

    return bytes(encoding) + encode_bytecode(ops, scheme)
