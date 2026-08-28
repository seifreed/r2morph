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

_INSTRUCTION_PART_COUNT = 2
_BINARY_OPERAND_COUNT = 2
_TERNARY_OPERAND_COUNT = 3
_BYTE_WIDTH_BITS = 8
_QWORD_WIDTH_BITS = 64
_MAX_SHIFT_COUNT = 63
_REGISTER_COUNT = 16


def _register_operand(name: str) -> tuple[int, int] | None:
    if name in REGISTER_INDEX:
        return (REGISTER_INDEX[name], 64) if name != "rsp" else None
    if name in REGISTER32_INDEX:
        return (REGISTER32_INDEX[name], 32) if name != "esp" else None
    return None


# Low-byte GP register spellings -> the 64-bit base register's context slot. A
# setcc writes only this low byte, preserving the slot's upper seven bytes. The
# legacy high-byte names (ah/bh/ch/dh, bits 8-15) and spl (rsp) are intentionally
# absent, so a setcc targeting them is left native rather than misplaced.
REGISTER8_INDEX: dict[str, int] = {
    "al": 0,
    "cl": 1,
    "dl": 2,
    "bl": 3,
    "bpl": 5,
    "sil": 6,
    "dil": 7,
    "r8b": 8,
    "r9b": 9,
    "r10b": 10,
    "r11b": 11,
    "r12b": 12,
    "r13b": 13,
    "r14b": 14,
    "r15b": 15,
}

# Word GP register spellings -> the 64-bit base register's context slot, the same
# indices as REGISTER8_INDEX. Used for register-source movzx/movsx (`movzx eax, cx`):
# the source's low word is the operand. sp (rsp, index 4) is intentionally absent.
REGISTER16_INDEX: dict[str, int] = {
    "ax": 0,
    "cx": 1,
    "dx": 2,
    "bx": 3,
    "bp": 5,
    "si": 6,
    "di": 7,
    "r8w": 8,
    "r9w": 9,
    "r10w": 10,
    "r11w": 11,
    "r12w": 12,
    "r13w": 13,
    "r14w": 14,
    "r15w": 15,
}

# Memory-source size prefix -> source width in bits for movzx/movsx/movsxd. dword
# only appears with movsxd (sign-extend dword->qword); movzx/movsx use byte/word.
_MOVX_SRC_SIZES: dict[str, int] = {"byte": 8, "word": 16, "dword": 32}

# setcc/cmov condition suffix -> the canonical branch condition the interpreter
# evaluates arithmetically from the captured RFLAGS (a key of the codegen's
# _JCC_CONDITION_BASE). Mirrors region._CONDITION with the leading ``j`` dropped;
# the aliases (nae->b, ng->le, ...) collapse to the same canonical form.
_CC_SUFFIX_TO_CONDITION: dict[str, str] = {
    "e": "je",
    "z": "je",
    "ne": "jne",
    "nz": "jne",
    "l": "jl",
    "nge": "jl",
    "ge": "jge",
    "nl": "jge",
    "g": "jg",
    "nle": "jg",
    "le": "jle",
    "ng": "jle",
    "b": "jb",
    "c": "jb",
    "nae": "jb",
    "ae": "jae",
    "nc": "jae",
    "nb": "jae",
    "be": "jbe",
    "na": "jbe",
    "a": "ja",
    "nbe": "ja",
    "s": "js",
    "ns": "jns",
    "o": "jo",
    "no": "jno",
    "p": "jp",
    "pe": "jp",
    "np": "jnp",
    "po": "jnp",
}


def _decode_setcc(disasm: str) -> tuple[str, str, int] | None:
    """Decode ``setcc reg8`` into ``("setcc", condition, dst_slot)``.

    Only a low-byte GP register destination is virtualized (the handler writes one
    byte of the destination's context slot); a memory or high-byte destination, or
    an unrecognized condition, returns None so the instruction stays native.
    """
    parts = disasm.split()
    if len(parts) != _INSTRUCTION_PART_COUNT or not parts[0].lower().startswith("set"):
        return None
    condition = _CC_SUFFIX_TO_CONDITION.get(parts[0].lower()[3:])
    if condition is None:
        return None
    slot = REGISTER8_INDEX.get(parts[1].strip().lower())
    return ("setcc", condition, slot) if slot is not None else None


def _decode_cmov(disasm: str) -> tuple[str, str, int, int, int] | None:
    """Decode ``cmovcc reg, reg`` into ``("cmov", condition, dst_slot, src_slot, width)``.

    Register-to-register only, both operands the same 32- or 64-bit width; a memory
    source, mismatched width, non-GP register, or unrecognized condition returns
    None so the instruction stays native.
    """
    parts = disasm.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or not parts[0].lower().startswith("cmov"):
        return None
    condition = _CC_SUFFIX_TO_CONDITION.get(parts[0].lower()[4:])
    if condition is None or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    dst = _register_operand(left)
    src = _register_operand(right)
    if dst is None or src is None or dst[1] != src[1]:
        return None
    return ("cmov", condition, dst[0], src[0], dst[1])


def _decode_register_source(slot: int, width: int, source: str) -> tuple[int, int, bool, int] | None:
    register = _register_operand(source)
    if register is not None:
        return (slot, register[0], False, width) if register[1] == width else None
    if any(marker in source for marker in ("[", "]", "rip", ":", "ptr")):
        return None
    try:
        immediate = int(source, 0)
    except ValueError:
        return None
    if not immediate_fits_width(immediate, width):
        return None
    return (slot, immediate, True, width)


def _decode_subregister_source(left: str, right: str) -> tuple[int, int, bool, int] | None:
    result: tuple[int, int, bool, int] | None = None
    for registers, width in ((REGISTER8_INDEX, 8), (REGISTER16_INDEX, 16)):
        if left not in registers:
            continue
        slot = registers[left]
        if right in registers:
            result = (slot, registers[right], False, width)
        elif width == _BYTE_WIDTH_BITS and not any(marker in right for marker in ("[", "]", "rip", ":", "ptr")):
            try:
                immediate = int(right, 0)
            except ValueError:
                immediate = 1 << _BYTE_WIDTH_BITS
            if immediate_fits_width(immediate, _BYTE_WIDTH_BITS):
                result = (slot, immediate, True, _BYTE_WIDTH_BITS)
        break
    return result


def _decode_two_operand(disasm: str, mnemonic: str) -> tuple[int, int, bool, int] | None:
    """Decode ``<mnemonic> reg, reg|imm`` into (slot, value, is_immediate, width)."""
    parts = disasm.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != mnemonic or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    destination = _register_operand(left)
    if destination is None:
        return _decode_subregister_source(left, right)
    return _decode_register_source(destination[0], destination[1], right)


def _decode_shift(disasm: str) -> tuple[str, int, int, int] | None:
    """Decode ``shl|shr|sar|rol|ror reg, imm8`` into (mnemonic, slot, count, width).

    Rotates share the stack-shift handler: the CPU runs the real ``rol``/``ror``, so
    the count masking and the flags match the native op bit-for-bit. ``rcl``/``rcr``
    (rotate *through carry*) are deliberately excluded - their carry-chained result is
    not a plain ``rol``/``ror`` and would misdecode.
    """
    parts = disasm.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("shl", "shr", "sar", "rol", "ror"):
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
    if count < 0 or count > _MAX_SHIFT_COUNT:
        return None
    return (mnemonic, slot, count, width)


def _decode_shift_reg(disasm: str) -> tuple[Any, ...] | None:
    """Decode a variable-count ``shl|shr|sar|rol|ror reg, cl`` into a shiftreg item.

    x86 variable shifts and rotates take their count only in ``cl``; the handler loads
    that count from the rcx slot at runtime and runs the real shift, so the CPU's count
    masking and flags (including the count == 0 case, which leaves the flags unchanged)
    match the native op. Returns ``("shiftreg", mnemonic, dst_slot, width)``.
    """
    parts = disasm.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("shl", "shr", "sar", "rol", "ror"):
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    if right != "cl":
        return None
    dst = _register_operand(left)
    if dst is None:
        return None
    return ("shiftreg", mnemonic, dst[0], dst[1])


def _decode_imul(disasm: str) -> tuple[int, int, int] | None:
    """Decode the two-operand register form ``imul reg, reg`` into (dst, src, width)."""
    parts = disasm.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "imul" or "," not in parts[1]:
        return None
    fields = parts[1].split(",")
    if len(fields) != _BINARY_OPERAND_COUNT:
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
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "push":
        return None
    operand = parts[1].strip().lower()
    reg = _register_operand(operand)
    if reg is not None:
        return ("push", reg[0], 64) if reg[1] == _QWORD_WIDTH_BITS else None
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
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
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
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "mov" or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    if right != "rsp":
        return None
    reg = _register_operand(left)
    if reg is None or reg[1] != _QWORD_WIDTH_BITS:
        return None
    return ("movfromrsp", reg[0])


def _decode_mov_to_rsp(disasm: str) -> tuple[Any, ...] | None:
    """Decode ``mov rsp, reg`` (frame teardown) into a VM item.

    The source is a 64-bit GP register (typically the frame pointer rbp); the rsp
    slot is set to its value, restoring the stack pointer to the saved frame.
    """
    parts = disasm.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "mov" or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    if left != "rsp":
        return None
    reg = _register_operand(right)
    if reg is None or reg[1] != _QWORD_WIDTH_BITS:
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
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "pop":
        return None
    reg = _register_operand(parts[1].strip().lower())
    if reg is None or reg[1] != _QWORD_WIDTH_BITS:
        return None
    return ("pop", reg[0], 64)


def _decode_imul3(disasm: str) -> tuple[int, int, int, int] | None:
    """Decode the three-operand form ``imul reg, reg, imm`` into (dst, src, imm, width).

    The immediate of a three-operand imul is an ``imm32`` sign-extended to the
    operand width, so it must fit a signed 32-bit value regardless of the
    destination width.
    """
    result: tuple[int, int, int, int] | None = None
    parts = disasm.split(None, 1)
    if len(parts) == _INSTRUCTION_PART_COUNT and parts[0].lower() == "imul":
        fields = parts[1].split(",")
        if len(fields) == _TERNARY_OPERAND_COUNT:
            destination = _register_operand(fields[0].strip().lower())
            source = _register_operand(fields[1].strip().lower())
            immediate_text = fields[2].strip().lower()
            if (
                destination is not None
                and source is not None
                and destination[1] == source[1]
                and not any(marker in immediate_text for marker in ("[", "]", "rip", ":", "ptr"))
            ):
                try:
                    immediate = int(immediate_text, 0)
                except ValueError:
                    immediate = 1 << 32
                if immediate_fits_width(immediate, 32):
                    result = (destination[0], source[0], immediate, destination[1])
    return result


_MEM_DISP_BOUND = 1 << 31  # displacement is encoded as a signed 32-bit value


def _parse_tls_operand(text: str) -> tuple[str, int | None, int, int | None] | None:
    """Parse an FS/GS address into segment, base register, displacement and width."""
    text = text.strip().lower()
    width: int | None = None
    head = text.split(None, 1)
    if head and head[0] in ("qword", "dword"):
        width = 64 if head[0] == "qword" else 32
        text = head[1].strip() if len(head) > 1 else ""
    rest = text.split(None, 1)
    if rest and rest[0] == "ptr":
        text = rest[1].strip() if len(rest) > 1 else ""
    if text.startswith(("fs:", "gs:")):
        segment, expression = text[:2], text[3:]
    elif text.startswith(("[fs:", "[gs:")) and text.endswith("]"):
        segment, expression = text[1:3], text[4:-1]
    else:
        return None
    if expression.startswith("[") and expression.endswith("]"):
        expression = expression[1:-1]
    base, displacement = expression.strip(), 0
    for sign, scale in (("+", 1), ("-", -1)):
        if sign in expression:
            base, right = expression.split(sign, 1)
            try:
                displacement = scale * int(right.strip(), 0)
            except ValueError:
                return None
            break
    base = base.strip()
    base_slot = REGISTER_INDEX.get(base) if base else None
    if base and base_slot is None:
        try:
            displacement = int(base, 0)
        except ValueError:
            return None
        base_slot = None
    if not -_MEM_DISP_BOUND <= displacement < _MEM_DISP_BOUND:
        return None
    return segment, base_slot, displacement, width


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
