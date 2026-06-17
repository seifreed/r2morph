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


def _parse_indexed_operand(text: str) -> tuple[int, int, int, int] | None:
    """Parse ``[base + index*scale + disp]`` into (base slot, index slot, scale
    shift, displacement).

    Both a base and a scaled index are required (the no-base and no-index forms
    are handled elsewhere or left native). The scale is encoded as its log2 so
    the interpreter can apply it with a shift. rip-relative and segment forms
    yield ``None``.
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
    if base is None or index is None or shift is None:
        return None
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
    parsed = _parse_indexed_operand(right)
    if parsed is None:
        return None
    base_slot, index_slot, shift, disp = parsed
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
