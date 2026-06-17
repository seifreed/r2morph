"""
Code virtualization engine - real, semantics-preserving register VM.

Transforms a straight-line run of 64-bit general-purpose register
instructions into bytecode for a small stack-context virtual machine.
The native run is replaced by a trampoline into a generated interpreter
that spills the architectural registers to a private stack frame,
executes the bytecode against that context, reloads the registers, and
jumps back to the instruction following the run.

Correctness contract (why this preserves semantics):

- Only 64-bit GP-register data/arithmetic ops are virtualized
  (``mov``/``add``/``sub``/``xor``/``and``/``or`` with register or
  immediate operands). Full-width 64-bit handlers reproduce the exact
  register effect; 32-bit width masking is intentionally out of scope
  (rejected, not approximated).
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

SUPPORTED_MNEMONICS: frozenset[str] = frozenset({"mov", "add", "sub", "xor", "and", "or"})

# VM opcodes. Register/immediate variants are distinct so the dispatcher
# never has to inspect operand encoding at runtime.
_OPCODES: dict[tuple[str, bool], int] = {
    ("mov", True): 0x01,
    ("mov", False): 0x02,
    ("add", True): 0x03,
    ("add", False): 0x04,
    ("sub", True): 0x05,
    ("sub", False): 0x06,
    ("xor", True): 0x07,
    ("xor", False): 0x08,
    ("and", True): 0x09,
    ("and", False): 0x0A,
    ("or", True): 0x0B,
    ("or", False): 0x0C,
}
_VM_EXIT = 0xFF

# Private stack frame the interpreter carves below the caller's rsp. The
# 16 context slots occupy [0x00, 0x80); the System V red zone
# [original_rsp-128, original_rsp) maps to [0x80, 0x100) and is left
# untouched, so leaf-function red-zone data survives the detour.
_FRAME_SIZE = 0x100


class VirtualizedOp:
    """A single decoded instruction destined for the VM bytecode."""

    __slots__ = ("mnemonic", "dst_index", "value", "is_immediate")

    def __init__(self, mnemonic: str, dst_index: int, value: int, is_immediate: bool) -> None:
        self.mnemonic = mnemonic
        self.dst_index = dst_index
        self.value = value
        self.is_immediate = is_immediate


def _normalize_operand(token: str) -> str:
    return token.strip().lower()


def _parse_immediate(token: str) -> int | None:
    token = token.strip()
    try:
        return int(token, 0)
    except ValueError:
        return None


def decode_instruction(disasm: str) -> VirtualizedOp | None:
    """
    Decode one disassembled instruction into a :class:`VirtualizedOp`.

    Returns ``None`` for anything the VM cannot reproduce exactly: a
    non-supported mnemonic, a non-64-bit-GP register, a memory/RIP/segment
    operand, or any ``rsp`` involvement.
    """
    text = disasm.strip()
    if " " not in text:
        return None

    mnemonic, operand_text = text.split(None, 1)
    mnemonic = mnemonic.lower()
    if mnemonic not in SUPPORTED_MNEMONICS:
        return None

    if "," not in operand_text:
        return None
    dst_token, src_token = operand_text.split(",", 1)
    dst = _normalize_operand(dst_token)
    src = _normalize_operand(src_token)

    if dst not in REGISTER_INDEX or dst == "rsp":
        return None

    if src in REGISTER_INDEX:
        if src == "rsp":
            return None
        return VirtualizedOp(mnemonic, REGISTER_INDEX[dst], REGISTER_INDEX[src], is_immediate=False)

    # Reject memory/RIP/segment operands - anything that is not a bare
    # 64-bit register or a plain immediate.
    if any(marker in src for marker in ("[", "]", "rip", ":", "ptr")):
        return None

    immediate = _parse_immediate(src)
    if immediate is None:
        return None
    if immediate < -(2**63) or immediate > 2**63 - 1:
        return None
    return VirtualizedOp(mnemonic, REGISTER_INDEX[dst], immediate, is_immediate=True)


def encode_bytecode(ops: list[VirtualizedOp]) -> bytes:
    """Serialize decoded ops to VM bytecode terminated by VM_EXIT."""
    stream = bytearray()
    for op in ops:
        stream.append(_OPCODES[(op.mnemonic, op.is_immediate)])
        stream.append(op.dst_index)
        if op.is_immediate:
            stream += struct.pack("<q", op.value)
        else:
            stream.append(op.value)
    stream.append(_VM_EXIT)
    return bytes(stream)


def _interpreter_asm(continuation_vaddr: int) -> str:
    """Generate the interpreter assembly for one virtualized run."""

    def handler_ri(operation: str) -> str:
        return (
            "  movzx r8d, byte ptr [rsi+1]\n"
            "  mov rax, qword ptr [rsi+2]\n"
            f"  {operation} qword ptr [rsp + r8*8], rax\n"
            "  add rsi, 10\n"
            "  jmp vm_dispatch\n"
        )

    def handler_rr(operation: str) -> str:
        return (
            "  movzx r8d, byte ptr [rsi+1]\n"
            "  movzx r9d, byte ptr [rsi+2]\n"
            "  mov rax, qword ptr [rsp + r9*8]\n"
            f"  {operation} qword ptr [rsp + r8*8], rax\n"
            "  add rsi, 3\n"
            "  jmp vm_dispatch\n"
        )

    lines = [f"vm_entry:\n  sub rsp, {_FRAME_SIZE}\n"]
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov qword ptr [rsp + {index * 8}], {name}\n")
    lines.append(
        f"  lea rax, [rsp + {_FRAME_SIZE}]\n"
        f"  mov qword ptr [rsp + {RSP_INDEX * 8}], rax\n"
        "  lea rsi, [rip + bytecode]\n"
        "vm_dispatch:\n"
        "  movzx eax, byte ptr [rsi]\n"
    )

    handler_label = {
        ("mov", True): "h_mov_ri",
        ("mov", False): "h_mov_rr",
        ("add", True): "h_add_ri",
        ("add", False): "h_add_rr",
        ("sub", True): "h_sub_ri",
        ("sub", False): "h_sub_rr",
        ("xor", True): "h_xor_ri",
        ("xor", False): "h_xor_rr",
        ("and", True): "h_and_ri",
        ("and", False): "h_and_rr",
        ("or", True): "h_or_ri",
        ("or", False): "h_or_rr",
    }
    for key, label in handler_label.items():
        lines.append(f"  cmp al, {_OPCODES[key]}\n  je {label}\n")
    lines.append("  jmp vm_exit\n")

    for (mnemonic, is_imm), label in handler_label.items():
        body = handler_ri(mnemonic) if is_imm else handler_rr(mnemonic)
        lines.append(f"{label}:\n{body}")

    lines.append("vm_exit:\n")
    for index, name in enumerate(GP_REGISTERS):
        if name != "rsp":
            lines.append(f"  mov {name}, qword ptr [rsp + {index * 8}]\n")
    lines.append(f"  add rsp, {_FRAME_SIZE}\n  jmp {hex(continuation_vaddr)}\nbytecode:\n")
    return "".join(lines)


def build_vm_blob(ops: list[VirtualizedOp], cave_vaddr: int, continuation_vaddr: int) -> bytes | None:
    """
    Assemble the interpreter at ``cave_vaddr`` and append the bytecode.

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

    asm = _interpreter_asm(continuation_vaddr)
    try:
        engine = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, _ = engine.asm(asm, cave_vaddr)
    except keystone.KsError as exc:
        logger.debug("VM interpreter assembly failed: %s", exc)
        return None
    if not encoding:
        logger.debug("VM interpreter assembly produced no bytes")
        return None

    return bytes(encoding) + encode_bytecode(ops)
