"""
Decoding of native instructions into region VM bytecode items.

Each function turns one disassembled instruction (or operand) into the tuple
the region encoder consumes, or returns None when the instruction falls
outside the VM's supported subset. These are pure text/structure parsers with
no dependency on the interpreter or the scheme;
:mod:`code_virtualization_region` calls them from its classifier.
"""

from __future__ import annotations

from typing import Any

from r2morph.mutations.code_virtualization_engine import (
    REGISTER32_INDEX,
    REGISTER_INDEX,
    immediate_fits_width,
)


def _register_operand(name: str) -> tuple[int, int] | None:
    if name in REGISTER_INDEX:
        return (REGISTER_INDEX[name], 64) if name != "rsp" else None
    if name in REGISTER32_INDEX:
        return (REGISTER32_INDEX[name], 32) if name != "esp" else None
    return None


def _decode_two_operand(disasm: str, mnemonic: str) -> tuple[int, int, bool, int] | None:
    """Decode ``<mnemonic> reg, reg|imm`` into (slot, value, is_immediate, width)."""
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != mnemonic or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    dst = _register_operand(left)
    if dst is None:
        return None
    slot, width = dst
    src = _register_operand(right)
    if src is not None:
        if src[1] != width:
            return None
        return (slot, src[0], False, width)
    if any(marker in right for marker in ("[", "]", "rip", ":", "ptr")):
        return None
    try:
        immediate = int(right, 0)
    except ValueError:
        return None
    if not immediate_fits_width(immediate, width):
        return None
    return (slot, immediate, True, width)


def _decode_shift(disasm: str) -> tuple[str, int, int, int] | None:
    """Decode ``shl|shr|sar reg, imm8`` into (mnemonic, slot, count, width)."""
    parts = disasm.split(None, 1)
    if len(parts) != 2 or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("shl", "shr", "sar"):
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    dst = _register_operand(left)
    if dst is None:
        return None
    slot, width = dst
    try:
        count = int(right, 0)
    except ValueError:
        return None  # register/cl counts are out of scope
    if count < 0 or count > 63:
        return None
    return (mnemonic, slot, count, width)


def _decode_imul(disasm: str) -> tuple[int, int, int] | None:
    """Decode the two-operand register form ``imul reg, reg`` into (dst, src, width)."""
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "imul" or "," not in parts[1]:
        return None
    fields = parts[1].split(",")
    if len(fields) != 2:
        return None  # one- or three-operand forms are out of scope
    dst = _register_operand(fields[0].strip().lower())
    src = _register_operand(fields[1].strip().lower())
    if dst is None or src is None or dst[1] != src[1]:
        return None
    return (dst[0], src[0], dst[1])


def _decode_push(disasm: str) -> tuple[Any, ...] | None:
    """Decode ``push reg`` (64-bit GP) or ``push imm`` into a VM item.

    rsp is rejected as an operand (``_register_operand`` returns ``None`` for
    it), so the pushed register is never the stack pointer. A memory-operand
    push is left native. The immediate form sign-extends an imm32.
    """
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "push":
        return None
    operand = parts[1].strip().lower()
    reg = _register_operand(operand)
    if reg is not None:
        return ("push", reg[0], 64) if reg[1] == 64 else None
    if any(marker in operand for marker in ("[", "]", "rip", ":", "ptr")):
        return None
    try:
        value = int(operand, 0)
    except ValueError:
        return None
    # ``push imm`` is an imm32 sign-extended to 64 bits; the disassembler prints
    # a negative immediate as its unsigned 64-bit form, so fold it back to signed
    # before checking it fits the imm32 the instruction actually encodes.
    if value >= 1 << 63:
        value -= 1 << 64
    return ("pushi", value, 64) if immediate_fits_width(value, 32) else None


def _decode_rsp_arith(disasm: str) -> tuple[Any, ...] | None:
    """Decode ``add rsp, imm`` / ``sub rsp, imm`` (stack frame allocation)."""
    parts = disasm.split(None, 1)
    if len(parts) != 2 or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("add", "sub"):
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    if left != "rsp" or any(marker in right for marker in ("[", "]", "rip", ":", "ptr")):
        return None
    try:
        value = int(right, 0)
    except ValueError:
        return None
    if value >= 1 << 63:
        value -= 1 << 64
    if value < 0 or not immediate_fits_width(value, 32):
        return None
    return ("rspadj", mnemonic, value)


def _decode_mov_from_rsp(disasm: str) -> tuple[Any, ...] | None:
    """Decode ``mov reg, rsp`` (frame-pointer setup) into a VM item.

    The destination is a 64-bit GP register (never rsp); it receives the
    program's current relocated stack pointer so later ``[reg+disp]`` accesses
    resolve through the same relocated base.
    """
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "mov" or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    if right != "rsp":
        return None
    reg = _register_operand(left)
    if reg is None or reg[1] != 64:
        return None
    return ("movfromrsp", reg[0])


def _decode_mov_to_rsp(disasm: str) -> tuple[Any, ...] | None:
    """Decode ``mov rsp, reg`` (frame teardown) into a VM item.

    The source is a 64-bit GP register (typically the frame pointer rbp); the rsp
    slot is set to its value, restoring the stack pointer to the saved frame.
    """
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "mov" or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    if left != "rsp":
        return None
    reg = _register_operand(right)
    if reg is None or reg[1] != 64:
        return None
    return ("movtorsp", reg[0])


def _decode_leave(disasm: str) -> tuple[Any, ...] | None:
    """Decode ``leave`` (``mov rsp, rbp`` followed by ``pop rbp``) into a VM item."""
    if disasm.strip().lower() != "leave":
        return None
    return ("leave", REGISTER_INDEX["rbp"])


def _decode_pop(disasm: str) -> tuple[Any, ...] | None:
    """Decode ``pop reg`` (64-bit GP, never rsp) into a VM item."""
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "pop":
        return None
    reg = _register_operand(parts[1].strip().lower())
    if reg is None or reg[1] != 64:
        return None
    return ("pop", reg[0], 64)


def _decode_imul3(disasm: str) -> tuple[int, int, int, int] | None:
    """Decode the three-operand form ``imul reg, reg, imm`` into (dst, src, imm, width).

    The immediate of a three-operand imul is an ``imm32`` sign-extended to the
    operand width, so it must fit a signed 32-bit value regardless of the
    destination width.
    """
    parts = disasm.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "imul":
        return None
    fields = parts[1].split(",")
    if len(fields) != 3:
        return None
    dst = _register_operand(fields[0].strip().lower())
    src = _register_operand(fields[1].strip().lower())
    if dst is None or src is None or dst[1] != src[1]:
        return None
    if any(marker in fields[2] for marker in ("[", "]", "rip", ":", "ptr")):
        return None
    try:
        immediate = int(fields[2].strip().lower(), 0)
    except ValueError:
        return None
    if not immediate_fits_width(immediate, 32):
        return None
    return (dst[0], src[0], immediate, dst[1])


_MEM_DISP_BOUND = 1 << 31  # displacement is encoded as a signed 32-bit value


def _parse_mem_operand(text: str) -> tuple[int, int, int | None] | None:
    """Parse ``[base+disp]`` into (base slot, displacement, width or None).

    Only a single 64-bit base register (any GP register, including rsp) plus an
    optional displacement is accepted. An index, scale, rip-relative form or
    segment override yields ``None`` - the run is then left native.
    """
    text = text.strip().lower()
    width: int | None = None
    head = text.split(None, 1)
    if head and head[0] in ("qword", "dword", "word", "byte", "xmmword", "tbyte"):
        if head[0] == "qword":
            width = 64
        elif head[0] == "dword":
            width = 32
        else:
            return None  # byte/word/xmmword widths are out of scope
        text = head[1].strip() if len(head) > 1 else ""
    rest = text.split(None, 1)
    if rest and rest[0] == "ptr":
        text = rest[1].strip() if len(rest) > 1 else ""
    if not (text.startswith("[") and text.endswith("]")):
        return None
    inner = text[1:-1].strip()
    if any(marker in inner for marker in ("*", "rip", ":")):
        return None  # index/scale, rip-relative, or segment override
    base, disp = inner, 0
    for sign, scale in (("+", 1), ("-", -1)):
        if sign in inner:
            left, right = inner.split(sign, 1)
            base = left.strip()
            try:
                disp = scale * int(right.strip(), 0)
            except ValueError:
                return None
            break
    base_slot = REGISTER_INDEX.get(base)
    if base_slot is None or not -_MEM_DISP_BOUND <= disp < _MEM_DISP_BOUND:
        return None
    return (base_slot, disp, width)


def _parse_xmm_operand(text: str) -> int | None:
    """Parse ``xmmN`` (0-15) into its register index, or ``None``."""
    text = text.strip().lower()
    if not text.startswith("xmm"):
        return None
    try:
        index = int(text[3:])
    except ValueError:
        return None
    return index if 0 <= index < 16 else None


def _decode_fp_mem(text: str) -> tuple[str, int, int, int, int] | None:
    """Decode ``movsd/movss xmm, [base+disp]`` / ``movsd/movss [base+disp], xmm``.

    Returns ``(kind, xmm_index, base_slot, disp, width)`` where ``kind`` is
    ``"fpload"`` or ``"fpstore"`` and ``width`` is 64 (movsd) or 32 (movss), or
    ``None`` for xmm-to-xmm moves, indexed/rip-relative addressing, or any other
    form. Only reached for ``family == "vec"`` instructions, so the no-operand
    string ``movsd`` never lands here.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or "," not in parts[1]:
        return None
    width = {"movsd": 64, "movss": 32}.get(parts[0].lower())
    if width is None:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None  # xmm-to-xmm or memory-to-memory are not loads/stores
    if left_mem:
        kind, mem_text, xmm_text = "fpstore", left, right
    else:
        kind, mem_text, xmm_text = "fpload", right, left
    xmm_index = _parse_xmm_operand(xmm_text)
    mem = _parse_mem_operand(mem_text)
    if xmm_index is None or mem is None:
        return None
    base_slot, disp, mem_width = mem
    if mem_width is not None and mem_width != width:
        return None
    return (kind, xmm_index, base_slot, disp, width)


_FP_ARITH_MNEMONICS: dict[str, tuple[str, int]] = {
    "addsd": ("add", 64),
    "subsd": ("sub", 64),
    "mulsd": ("mul", 64),
    "divsd": ("div", 64),
    "addss": ("add", 32),
    "subss": ("sub", 32),
    "mulss": ("mul", 32),
    "divss": ("div", 32),
}


def _decode_fp_arith(text: str) -> tuple[str, str, int, int, int] | None:
    """Decode scalar-FP register-register arithmetic
    (``addsd/subsd/mulsd/divsd`` and ``ss`` forms).

    Returns ``(kind, op, dst_index, src_index, width)`` with ``kind == "fparith"``,
    ``op`` one of add/sub/mul/div, or ``None`` for a memory source (left native)
    or any other form. r2 types subsd/divsd as ``null``, so the mnemonic - not the
    instruction type - is the reliable discriminator; only reached for vec family.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or "," not in parts[1]:
        return None
    spec = _FP_ARITH_MNEMONICS.get(parts[0].lower())
    if spec is None:
        return None
    op, width = spec
    left, right = (token.strip() for token in parts[1].split(",", 1))
    dst_index = _parse_xmm_operand(left)
    src_index = _parse_xmm_operand(right)  # register source only; a memory source yields None
    if dst_index is None or src_index is None:
        return None
    return ("fparith", op, dst_index, src_index, width)


# FP precision (sd=64, ss=32) of each conversion mnemonic.
_CVT_INT_TO_FP: dict[str, int] = {"cvtsi2sd": 64, "cvtsi2ss": 32}
_CVT_FP_TO_INT: dict[str, int] = {"cvttsd2si": 64, "cvttss2si": 32}


def _decode_fp_convert(text: str) -> tuple[str, int, int, int] | None:
    """Decode int<->float conversions with a 64-bit GP register operand.

    ``cvtsi2sd/ss xmm, r64`` -> ``("cvti2f", fp_width, xmm_index, gp_slot)`` and
    ``cvttsd2si/ss r64, xmm`` -> ``("cvtf2i", fp_width, gp_slot, xmm_index)``.
    Returns ``None`` for a memory operand, a 32-bit GP register, rsp, or any other
    form (left native). These mnemonics are type ``null`` and inconsistently typed
    family (cpu for the r64 cvtsi2sd), so the mnemonic is the only reliable gate -
    hence this is tried ahead of the family check, not behind it.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    left, right = (token.strip() for token in parts[1].split(",", 1))
    if mnemonic in _CVT_INT_TO_FP:
        xmm_index = _parse_xmm_operand(left)
        gp = _register_operand(right.lower())  # 64-bit GP only (not rsp); 32-bit -> native
        if xmm_index is None or gp is None:
            return None
        return ("cvti2f", _CVT_INT_TO_FP[mnemonic], xmm_index, gp[0])
    if mnemonic in _CVT_FP_TO_INT:
        gp = _register_operand(left.lower())
        xmm_index = _parse_xmm_operand(right)
        if gp is None or xmm_index is None:
            return None
        return ("cvtf2i", _CVT_FP_TO_INT[mnemonic], gp[0], xmm_index)
    return None


_FP_COMPARE_MNEMONICS: frozenset[str] = frozenset({"ucomisd", "comisd", "ucomiss", "comiss"})


def _decode_fp_compare(text: str) -> tuple[str, str, int, int] | None:
    """Decode a scalar-FP register-register compare (``ucomisd``/``comisd`` and
    the ``ss`` forms) into ``("fpcmp", mnemonic, left_index, right_index)``.

    Returns ``None`` for a memory operand or any other form (left native). The
    mnemonic is preserved so the handler emits the exact compare, which sets the
    real ZF/PF/CF (including the unordered/NaN case) for the existing branch path.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in _FP_COMPARE_MNEMONICS:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_index = _parse_xmm_operand(left)
    right_index = _parse_xmm_operand(right)  # register-register only; a memory operand yields None
    if left_index is None or right_index is None:
        return None
    return ("fpcmp", mnemonic, left_index, right_index)


def _decode_memory_mov(text: str) -> tuple[str, int, int, int, int] | None:
    """Decode ``mov reg, [base+disp]`` / ``mov [base+disp], reg``.

    Returns ``(kind, reg_slot, base_slot, disp, width)`` where ``kind`` is
    ``"load"`` or ``"store"``, or ``None`` for anything else (two memory
    operands, a partial-width access, a non-GP register, etc.).
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "mov" or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None  # register-to-register or memory-to-memory are not loads/stores
    if left_mem:
        kind, mem_text, reg_text = "store", left, right
    else:
        kind, mem_text, reg_text = "load", right, left
    mem = _parse_mem_operand(mem_text)
    reg = _register_operand(reg_text.lower())
    if mem is None or reg is None:
        return None
    base_slot, disp, mem_width = mem
    reg_slot, reg_width = reg
    if mem_width is not None and mem_width != reg_width:
        return None
    return (kind, reg_slot, base_slot, disp, reg_width)


def _parse_riprel_operand(text: str, insn_addr: int, insn_size: int) -> tuple[int, int | None] | None:
    """Parse ``[rip+disp]`` into (absolute target vaddr, width or None).

    The target is resolved against the original instruction (``rip`` points at
    the next instruction): ``addr + size + disp``. The VM relocates the code, so
    the absolute target is later re-expressed relative to the bytecode base,
    which stays base-independent because the global and the VM live in one image.
    """
    text = text.strip().lower()
    width: int | None = None
    head = text.split(None, 1)
    if head and head[0] in ("qword", "dword", "word", "byte", "xmmword", "tbyte"):
        if head[0] == "qword":
            width = 64
        elif head[0] == "dword":
            width = 32
        else:
            return None
        text = head[1].strip() if len(head) > 1 else ""
    rest = text.split(None, 1)
    if rest and rest[0] == "ptr":
        text = rest[1].strip() if len(rest) > 1 else ""
    if not (text.startswith("[") and text.endswith("]")):
        return None
    inner = text[1:-1].strip()
    if not inner.startswith("rip") or "*" in inner or ":" in inner:
        return None
    tail = inner[len("rip") :].strip()
    disp = 0
    if tail:
        if tail[0] not in "+-":
            return None
        try:
            disp = (1 if tail[0] == "+" else -1) * int(tail[1:].strip(), 0)
        except ValueError:
            return None
    return (insn_addr + insn_size + disp, width)


def _decode_riprel_mov(text: str, insn_addr: int, insn_size: int) -> tuple[str, int, int, int] | None:
    """Decode ``mov reg, [rip+disp]`` / ``mov [rip+disp], reg``.

    Returns ``(kind, reg_slot, target_vaddr, width)`` with ``kind`` either
    ``"riprel_load"`` or ``"riprel_store"``, or ``None``.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "mov" or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None
    if left_mem:
        kind, mem_text, reg_text = "riprel_store", left, right
    else:
        kind, mem_text, reg_text = "riprel_load", right, left
    parsed = _parse_riprel_operand(mem_text, insn_addr, insn_size)
    reg = _register_operand(reg_text.lower())
    if parsed is None or reg is None:
        return None
    target, mem_width = parsed
    reg_slot, reg_width = reg
    if mem_width is not None and mem_width != reg_width:
        return None
    return (kind, reg_slot, target, reg_width)


def _decode_cmp_mem(text: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode ``cmp reg, [base+disp]`` / ``cmp reg, [rip+disp]``.

    Returns ``("cmpmem", reg_slot, base_slot, disp, width)`` or
    ``("cmpriprel", reg_slot, target, width)``, or ``None``. Only a register
    left operand against a memory right operand is accepted.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "cmp" or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    if "[" in left or "[" not in right:
        return None
    reg = _register_operand(left.lower())
    if reg is None:
        return None
    reg_slot, reg_width = reg
    mem = _parse_mem_operand(right)
    if mem is not None:
        base_slot, disp, mem_width = mem
        if mem_width is not None and mem_width != reg_width:
            return None
        return ("cmpmem", reg_slot, base_slot, disp, reg_width)
    riprel = _parse_riprel_operand(right, insn_addr, insn_size)
    if riprel is not None:
        target, mem_width = riprel
        if mem_width is not None and mem_width != reg_width:
            return None
        return ("cmpriprel", reg_slot, target, reg_width)
    return None


def _decode_op_mem(text: str, mnemonic: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode ``<op> reg, [base+disp]`` / ``<op> reg, [rip+disp]`` for an
    arithmetic mnemonic, where the register is both source and destination.

    Returns ``("opmem", mnemonic, reg_slot, base_slot, disp, width)`` or
    ``("opriprel", mnemonic, reg_slot, target, width)``, or ``None``.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != mnemonic or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    if "[" in left or "[" not in right:
        return None
    reg = _register_operand(left.lower())
    if reg is None:
        return None
    reg_slot, reg_width = reg
    mem = _parse_mem_operand(right)
    if mem is not None:
        base_slot, disp, mem_width = mem
        if mem_width is not None and mem_width != reg_width:
            return None
        return ("opmem", mnemonic, reg_slot, base_slot, disp, reg_width)
    riprel = _parse_riprel_operand(right, insn_addr, insn_size)
    if riprel is not None:
        target, mem_width = riprel
        if mem_width is not None and mem_width != reg_width:
            return None
        return ("opriprel", mnemonic, reg_slot, target, reg_width)
    return None


def _decode_movx(text: str) -> tuple[Any, ...] | None:
    """Decode ``movzx/movsx reg, byte|word [base+disp]`` (memory source).

    r2 reports movzx/movsx under the mov type. The destination is a 32- or
    64-bit register; the source is a byte or word in memory. Returns
    ``("movx", ext, src_size, dst_width, reg_slot, base_slot, disp)`` where
    ``ext`` is ``"z"`` or ``"s"``, or ``None``.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("movzx", "movsx"):
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    dst = _register_operand(left.lower())
    if dst is None:
        return None
    size_word, _, remainder = right.lower().partition(" ")
    if size_word == "byte":
        src_size = 8
    elif size_word == "word":
        src_size = 16
    else:
        return None
    ext = "z" if mnemonic == "movzx" else "s"
    mem = _parse_mem_operand(remainder.strip())
    if mem is not None:
        base_slot, disp, _mem_width = mem
        return ("movx", ext, src_size, dst[1], dst[0], base_slot, disp)
    indexed = _parse_indexed_operand(remainder.strip())
    if indexed is not None:
        base_slot, index_slot, shift, disp = indexed
        return ("movxidx", ext, src_size, dst[1], dst[0], base_slot, index_slot, shift, disp)
    return None


def _decode_incdec(text: str) -> tuple[Any, ...] | None:
    """Decode ``inc reg`` / ``dec reg`` (register operand).

    r2 reports inc/dec under the add/sub types, so this is tried in the
    arithmetic path. inc/dec preserve CF (unlike add/sub by one), so the handler
    runs the real instruction. Returns ``("incdec", mnemonic, reg_slot, width)``.
    """
    parts = text.split()
    if len(parts) != 2:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("inc", "dec") or "[" in parts[1]:
        return None
    reg = _register_operand(parts[1].lower())
    if reg is None:
        return None
    return ("incdec", mnemonic, reg[0], reg[1])


def _decode_op_memdst(text: str, mnemonic: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode ``<op> [base+disp], reg`` / ``<op> [rip+disp], reg`` (memory is the
    read-modify-write destination, the register is the source).

    Returns ``("opmemdst", mnemonic, reg_slot, base_slot, disp, width)`` or
    ``("opmemdstrip", mnemonic, reg_slot, target, width)``, or ``None``.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != mnemonic or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    if "[" not in left or "[" in right:
        return None
    reg = _register_operand(right.lower())
    if reg is None:
        return None
    reg_slot, reg_width = reg
    mem = _parse_mem_operand(left)
    if mem is not None:
        base_slot, disp, mem_width = mem
        if mem_width is not None and mem_width != reg_width:
            return None
        return ("opmemdst", mnemonic, reg_slot, base_slot, disp, reg_width)
    riprel = _parse_riprel_operand(left, insn_addr, insn_size)
    if riprel is not None:
        target, mem_width = riprel
        if mem_width is not None and mem_width != reg_width:
            return None
        return ("opmemdstrip", mnemonic, reg_slot, target, reg_width)
    return None


_SCALE_TO_SHIFT = {1: 0, 2: 1, 4: 2, 8: 3}


def _parse_indexed_operand(text: str, base_optional: bool = False) -> tuple[int, int, int, int] | None:
    """Parse ``[base + index*scale + disp]`` into (base slot, index slot, scale
    shift, displacement).

    A scaled index is always required. A base is required unless
    ``base_optional`` is set, in which case the no-base form ``[index*scale +
    disp]`` is accepted and the base slot is returned as ``-1`` (the caller
    routes that to a no-base handler). The scale is encoded as its log2 so the
    interpreter can apply it with a shift. rip-relative and segment forms yield
    ``None``.
    """
    text = text.strip().lower()
    head = text.split(None, 1)
    if head and head[0] in ("qword", "dword", "word", "byte", "xmmword", "tbyte"):
        if head[0] not in ("qword", "dword"):
            return None
        text = head[1].strip() if len(head) > 1 else ""
    rest = text.split(None, 1)
    if rest and rest[0] == "ptr":
        text = rest[1].strip() if len(rest) > 1 else ""
    if not (text.startswith("[") and text.endswith("]")):
        return None
    inner = text[1:-1].strip()
    if ":" in inner or "rip" in inner:
        return None
    base: int | None = None
    index: int | None = None
    shift: int | None = None
    disp = 0
    for token in (part.strip() for part in inner.replace("-", "+-").split("+")):
        if not token:
            continue
        token = token.replace(" ", "")
        if "*" in token:
            index_name, scale_text = token.split("*", 1)
            if index_name not in REGISTER_INDEX:
                return None
            try:
                scale = int(scale_text, 0)
            except ValueError:
                return None
            if scale not in _SCALE_TO_SHIFT:
                return None
            index, shift = REGISTER_INDEX[index_name], _SCALE_TO_SHIFT[scale]
        elif token in REGISTER_INDEX:
            # First bare register is the base; a second is an unscaled index.
            if base is None:
                base = REGISTER_INDEX[token]
            elif index is None:
                index, shift = REGISTER_INDEX[token], 0
            else:
                return None
        else:
            try:
                disp += int(token, 0)
            except ValueError:
                return None
    if index is None or shift is None:
        return None
    if base is None:
        return (-1, index, shift, disp) if base_optional else None
    return (base, index, shift, disp)


def _decode_op_mem_indexed(text: str, mnemonic: str) -> tuple[Any, ...] | None:
    """Decode ``<op> reg, [base + index*scale + disp]`` (scaled-index memory
    source, register source/destination).

    Returns ``("opmemidx", mnemonic, reg_slot, base_slot, index_slot, shift,
    disp, width)`` or ``None``.
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != mnemonic or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    if "[" in left or "[" not in right:
        return None
    reg = _register_operand(left.lower())
    if reg is None:
        return None
    parsed = _parse_indexed_operand(right)
    if parsed is None:
        return None
    base_slot, index_slot, shift, disp = parsed
    return ("opmemidx", mnemonic, reg[0], base_slot, index_slot, shift, disp, reg[1])


def _decode_lea_indexed(text: str) -> tuple[Any, ...] | None:
    """Decode ``lea reg, [base + index*scale + disp]`` (32- or 64-bit dst)."""
    parts = text.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "lea" or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    if "[" in left or "[" not in right:
        return None
    reg = _register_operand(left.lower())
    if reg is None:
        return None
    parsed = _parse_indexed_operand(right, base_optional=True)
    if parsed is None:
        return None
    base_slot, index_slot, shift, disp = parsed
    if base_slot == -1:
        return ("leaidxnb", reg[0], index_slot, shift, disp, reg[1])
    return ("leaidx", reg[0], base_slot, index_slot, shift, disp, reg[1])


def _decode_lea(text: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode ``lea reg, [base+disp]`` / ``lea reg, [rip+disp]`` (32- or 64-bit dst).

    ``lea`` computes an address without dereferencing memory and sets no flags.
    A 32-bit destination truncates the computed address to its low 32 bits
    (zero-extended), so the destination width is carried in the item. Returns
    ``("lea", reg_slot, base_slot, disp, width)`` or ``("learip", reg_slot,
    target, width)``, or ``None`` (index/scale forms are handled elsewhere).
    """
    parts = text.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "lea" or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    if "[" in left or "[" not in right:
        return None
    reg = _register_operand(left.lower())
    if reg is None:
        return None
    reg_slot, width = reg
    mem = _parse_mem_operand(right)
    if mem is not None:
        base_slot, disp, _mem_width = mem
        return ("lea", reg_slot, base_slot, disp, width)
    riprel = _parse_riprel_operand(right, insn_addr, insn_size)
    if riprel is not None:
        return ("learip", reg_slot, riprel[0], width)
    return None
