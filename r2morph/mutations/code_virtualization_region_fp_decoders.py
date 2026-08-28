"""Floating-point and SIMD instruction decoders for region virtualization."""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_decoders import (
    _INSTRUCTION_PART_COUNT,
    _REGISTER_COUNT,
    _parse_mem_operand,
    _register_operand,
)
from r2morph.mutations.code_virtualization_region_memory_decoders import (
    _parse_indexed_operand,
    _parse_riprel_operand,
)


def _parse_xmm_operand(text: str) -> int | None:
    """Parse ``xmmN`` (0-15) into its register index, or ``None``."""
    text = text.strip().lower()
    if not text.startswith("xmm"):
        return None
    try:
        index = int(text[3:])
    except ValueError:
        return None
    return index if 0 <= index < _REGISTER_COUNT else None


def _decode_fp_mem(text: str) -> tuple[str, int, int, int, int] | None:
    """Decode ``movsd/movss xmm, [base+disp]`` / ``movsd/movss [base+disp], xmm``.

    Returns ``(kind, xmm_index, base_slot, disp, width)`` where ``kind`` is
    ``"fpload"`` or ``"fpstore"`` and ``width`` is 64 (movsd) or 32 (movss), or
    ``None`` for xmm-to-xmm moves, indexed/rip-relative addressing, or any other
    form. Only reached for ``family == "vec"`` instructions, so the no-operand
    string ``movsd`` never lands here.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
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
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
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


def _decode_fp_convert(text: str) -> tuple[str, int, int, int, int] | None:
    """Decode int<->float conversions with a 32- or 64-bit GP register operand.

    ``cvtsi2sd/ss xmm, r`` -> ``("cvti2f", fp_width, gp_width, xmm_index, gp_slot)``
    and ``cvttsd2si/ss r, xmm`` -> ``("cvtf2i", fp_width, gp_width, gp_slot,
    xmm_index)``. Returns ``None`` for a memory operand, rsp/esp, or any other form
    (left native). The GP width matters: a 32-bit cvtsi2sd converts only the int32,
    and a 32-bit cvttsd2si saturates out-of-range doubles to 0x80000000. These
    mnemonics are type ``null`` and inconsistently typed family (cpu for the r64
    cvtsi2sd), so the mnemonic is the only reliable gate - hence this is tried
    ahead of the family check, not behind it.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    left, right = (token.strip() for token in parts[1].split(",", 1))
    if mnemonic in _CVT_INT_TO_FP:
        xmm_index = _parse_xmm_operand(left)
        gp = _register_operand(right.lower())  # 32- or 64-bit GP (not rsp/esp)
        if xmm_index is None or gp is None:
            return None
        return ("cvti2f", _CVT_INT_TO_FP[mnemonic], gp[1], xmm_index, gp[0])
    if mnemonic in _CVT_FP_TO_INT:
        gp = _register_operand(left.lower())
        xmm_index = _parse_xmm_operand(right)
        if gp is None or xmm_index is None:
            return None
        return ("cvtf2i", _CVT_FP_TO_INT[mnemonic], gp[1], gp[0], xmm_index)
    return None


_FP_COMPARE_MNEMONICS: frozenset[str] = frozenset({"ucomisd", "comisd", "ucomiss", "comiss", "ptest"})


def _decode_fp_compare(text: str) -> tuple[str, str, int, int] | None:
    """Decode a scalar-FP register-register compare (``ucomisd``/``comisd`` and
    the ``ss`` forms) and ``ptest`` into ``("fpcmp", mnemonic, left_index,
    right_index)``.

    Returns ``None`` for a memory operand or any other form (left native). The
    mnemonic is preserved so the handler emits the exact compare, which sets the
    real ZF/PF/CF (including the unordered/NaN case) for the existing branch path.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
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


def _decode_fp_compare_mem(text: str) -> tuple[str, str, int, int, int, int] | None:
    """Decode scalar-FP compare with a base-plus-displacement memory source.

    Returns ``("fpcmpmem", mnemonic, xmm_index, base_slot, displacement, width)``.
    The memory operand is kept as a separate form so the handler can preserve the
    exact compare flags without first materializing the value in another XMM slot.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    widths = {
        "ucomisd": 64,
        "comisd": 64,
        "ucomiss": 32,
        "comiss": 32,
    }
    mnemonic = parts[0].lower()
    width = widths.get(mnemonic)
    if width is None:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    xmm_index = _parse_xmm_operand(left)
    memory = _parse_mem_operand(right)
    if xmm_index is None or memory is None:
        return None
    base_slot, displacement, memory_width = memory
    if memory_width is not None and memory_width != width:
        return None
    return ("fpcmpmem", mnemonic, xmm_index, base_slot, displacement, width)


# Full 128-bit xmm-xmm copies vs scalar copies that preserve the destination's
# upper lane(s). (movsd/movss xmm,xmm preserve the high lanes, unlike the memory
# load forms which zero them - so they get the "sd"/"ss" preserving handler.)
_FP_MOVE_FULL: frozenset[str] = frozenset({"movaps", "movapd", "movups", "movupd"})
_FP_MOVE_SCALAR: dict[str, str] = {"movsd": "sd", "movss": "ss"}


def _decode_fp_move(text: str) -> tuple[str, str, int, int] | None:
    """Decode a register-register xmm move into ``("fpmov", mode, dst, src)``.

    ``mode`` is ``"full"`` (movaps/movapd/movups/movupd, full 128-bit copy) or
    ``"sd"``/``"ss"`` (movsd/movss, low element copied, destination upper lanes
    preserved). Returns ``None`` for a memory operand (handled as load/store) or
    any non-move mnemonic.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    left, right = (token.strip() for token in parts[1].split(",", 1))
    dst_index = _parse_xmm_operand(left)
    src_index = _parse_xmm_operand(right)  # register-register only
    if dst_index is None or src_index is None:
        return None
    if mnemonic in _FP_MOVE_FULL:
        return ("fpmov", "full", dst_index, src_index)
    if mnemonic in _FP_MOVE_SCALAR:
        return ("fpmov", _FP_MOVE_SCALAR[mnemonic], dst_index, src_index)
    return None


def _decode_fp_riprel(text: str, insn_addr: int, insn_size: int) -> tuple[str, int, int, int] | None:
    """Decode ``movsd/movss xmm, [rip+disp]`` / ``[rip+disp], xmm`` into
    ``("fploadrip"|"fpstorerip", xmm_index, target_vaddr, width)``.

    FP constants and globals live in .rodata/.data and are reached rip-relative;
    the absolute target is later re-expressed relative to the bytecode base.
    Returns ``None`` for a register or base+disp operand (other paths) or any
    non-movsd/movss mnemonic.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    width = {"movsd": 64, "movss": 32}.get(parts[0].lower())
    if width is None:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None
    if left_mem:
        kind, mem_text, xmm_text = "fpstorerip", left, right
    else:
        kind, mem_text, xmm_text = "fploadrip", right, left
    parsed = _parse_riprel_operand(mem_text, insn_addr, insn_size)
    xmm_index = _parse_xmm_operand(xmm_text)
    if parsed is None or xmm_index is None:
        return None
    target, mem_width = parsed
    if mem_width is not None and mem_width != width:
        return None
    return (kind, xmm_index, target, width)


def _decode_fp_arith_mem(text: str) -> tuple[str, str, int, int, int, int] | None:
    """Decode scalar-FP arithmetic with a ``[base+disp]`` memory source
    (``addsd xmm, [base+disp]`` etc.) into
    ``("fparithmem", op, xmm_index, base_slot, disp, width)``.

    Returns ``None`` for a register source (the reg-reg path), a rip-relative or
    indexed operand (left native, deferred), or any non-FP-arith mnemonic.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    spec = _FP_ARITH_MNEMONICS.get(parts[0].lower())
    if spec is None:
        return None
    op, width = spec
    left, right = (token.strip() for token in parts[1].split(",", 1))
    xmm_index = _parse_xmm_operand(left)
    mem = _parse_mem_operand(right)
    if xmm_index is None or mem is None:
        return None
    base_slot, disp, mem_width = mem
    if mem_width is not None and mem_width != width:
        return None
    return ("fparithmem", op, xmm_index, base_slot, disp, width)


def _decode_fp_arith_riprel(text: str, insn_addr: int, insn_size: int) -> tuple[str, str, int, int, int] | None:
    """Decode scalar-FP arithmetic with a rip-relative source
    (``addsd xmm, [rip+disp]`` etc.) into
    ``("fparithmemrip", op, xmm_index, target_vaddr, width)``.

    The constant-pool form: an FP constant in .rodata added straight to a register.
    Returns ``None`` for a register or base+disp source, or any non-FP-arith
    mnemonic. The target is re-expressed relative to the bytecode base later.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    spec = _FP_ARITH_MNEMONICS.get(parts[0].lower())
    if spec is None:
        return None
    op, width = spec
    left, right = (token.strip() for token in parts[1].split(",", 1))
    xmm_index = _parse_xmm_operand(left)
    parsed = _parse_riprel_operand(right, insn_addr, insn_size)
    if xmm_index is None or parsed is None:
        return None
    target, mem_width = parsed
    if mem_width is not None and mem_width != width:
        return None
    return ("fparithmemrip", op, xmm_index, target, width)


# The two shapes a scaled-index FP memory item can take. The no-base form has no
# ``base_slot`` field, so every field after it sits one position earlier; consumers
# select the layout from the ``nb`` suffix on the kind.
FpIndexedItem = tuple[str, int, int, int, int, int, int]
"""(kind, xmm_index, base_slot, index_slot, shift, disp, width)."""

FpIndexedNoBaseItem = tuple[str, int, int, int, int, int]
"""(kind + "nb", xmm_index, index_slot, shift, disp, width)."""


def _decode_fp_indexed(text: str) -> FpIndexedItem | FpIndexedNoBaseItem | None:
    """Decode ``movsd/movss xmm, [base+index*scale+disp]`` / store into
    ``("fploadidx"|"fpstoreidx", xmm_index, base_slot, index_slot, shift, disp,
    width)``.

    Scaled-index addressing is how arrays of double/float are accessed
    (``a[i]`` -> ``[base + i*8]``). The no-base form ``[index*scale+disp]`` lowers
    to the ``idxnb`` kinds (one byte shorter, no base slot), which drop the
    ``base_slot`` field and so carry ``width`` one position earlier. Returns
    ``None`` for a register or non-indexed operand.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    width = {"movsd": 64, "movss": 32}.get(parts[0].lower())
    if width is None:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None
    if left_mem:
        kind, mem_text, xmm_text = "fpstoreidx", left, right
    else:
        kind, mem_text, xmm_text = "fploadidx", right, left
    xmm_index = _parse_xmm_operand(xmm_text)
    indexed = _parse_indexed_operand(mem_text, base_optional=True)
    if xmm_index is None or indexed is None:
        return None
    base_slot, index_slot, shift, disp = indexed
    if base_slot < 0:
        # No base register: index*scale + disp. The item carries no base slot.
        return (kind + "nb", xmm_index, index_slot, shift, disp, width)
    return (kind, xmm_index, base_slot, index_slot, shift, disp, width)


def _decode_fp_arith_idx(text: str) -> tuple[str, str, int, int, int, int, int, int] | None:
    """Decode scalar-FP arithmetic with a scaled-index source
    (``addsd xmm, [base+index*scale+disp]`` etc.) into
    ``("fparithmemidx", op, xmm_index, base_slot, index_slot, shift, disp, width)``.

    The FP accumulation form (``sum += a[i]``). Returns ``None`` for a register,
    base+disp or rip-relative source, or any non-FP-arith mnemonic.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    spec = _FP_ARITH_MNEMONICS.get(parts[0].lower())
    if spec is None:
        return None
    op, width = spec
    left, right = (token.strip() for token in parts[1].split(",", 1))
    xmm_index = _parse_xmm_operand(left)
    indexed = _parse_indexed_operand(right)
    if xmm_index is None or indexed is None:
        return None
    base_slot, index_slot, shift, disp = indexed
    return ("fparithmemidx", op, xmm_index, base_slot, index_slot, shift, disp, width)


_FP_PACKED_ARITH: frozenset[str] = frozenset(
    {
        "addpd",
        "addps",
        "subpd",
        "subps",
        "mulpd",
        "mulps",
        "divpd",
        "divps",
        "paddd",
        "psubd",
        "paddb",
        "psubb",
        "paddw",
        "psubw",
        "paddq",
        "psubq",
        "pmulld",
        "pminsd",
        "pmaxsd",
        "pcmpeqd",
        "pcmpgtd",
        "pslld",
        "psrld",
        "psrad",
        "pand",
        "pandn",
        "por",
        "pxor",
    }
)
_FP_PACKED_MOVE: frozenset[str] = frozenset({"movaps", "movups", "movapd", "movupd"})


def _decode_fp_packed_arith(text: str) -> tuple[str, str, int, int] | None:
    """Decode a packed-FP register-register arithmetic op (``addpd``/``addps`` and
    the sub/mul/div forms) into ``("fppacked", mnemonic, dst_index, src_index)``.

    Operates on all lanes of the 128-bit register. Returns ``None`` for a memory
    operand (deferred) or any non-packed-arith mnemonic.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in _FP_PACKED_ARITH:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    dst_index = _parse_xmm_operand(left)
    src_index = _parse_xmm_operand(right)  # register-register only
    if dst_index is None or src_index is None:
        return None
    return ("fppacked", mnemonic, dst_index, src_index)


def _decode_fp_packed_arith_mem(text: str) -> tuple[str, str, int, int, int] | None:
    """Decode packed-FP arithmetic with a ``[base+disp]`` memory source
    (``addpd xmm, [base+disp]`` etc.) into
    ``("fppackedmem", mnemonic, xmm_index, base_slot, disp)``.

    The vectorized accumulation form. Returns ``None`` for a register, rip-relative
    or indexed source, or any non-packed-arith mnemonic.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in _FP_PACKED_ARITH:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    xmm_index = _parse_xmm_operand(left)
    if xmm_index is None or "[" not in right:
        return None
    mem = _parse_mem_operand(right.lower().replace("xmmword", ""))
    if mem is None:
        return None
    base_slot, disp, _width = mem
    return ("fppackedmem", mnemonic, xmm_index, base_slot, disp)


def _decode_fp_packed_arith_riprel(text: str, insn_addr: int, insn_size: int) -> tuple[str, str, int, int] | None:
    """Decode packed-FP arithmetic with a rip-relative source
    (``addpd xmm, [rip+disp]`` etc.) into
    ``("fppackedmemrip", mnemonic, xmm_index, target_vaddr)`` - a packed constant
    vector from .rodata added to a register. Returns ``None`` otherwise.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in _FP_PACKED_ARITH:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    xmm_index = _parse_xmm_operand(left)
    if xmm_index is None or "[" not in right:
        return None
    parsed = _parse_riprel_operand(right.lower().replace("xmmword", ""), insn_addr, insn_size)
    if parsed is None:
        return None
    target, _width = parsed
    return ("fppackedmemrip", mnemonic, xmm_index, target)


def _decode_fp_packed_indexed(text: str) -> tuple[str, int, int, int, int, int] | None:
    """Decode a scaled-index packed 128-bit move (``movaps``/``movups`` etc.
    xmm <-> [base+index*scale+disp]) into ``("fpploadidx"|"fppstoreidx",
    xmm_index, base_slot, index_slot, shift, disp)`` - access into an array of
    vectors. Returns ``None`` for a register, base+disp or rip-relative operand.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    if parts[0].lower() not in _FP_PACKED_MOVE:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None
    if left_mem:
        kind, mem_text, xmm_text = "fppstoreidx", left, right
    else:
        kind, mem_text, xmm_text = "fpploadidx", right, left
    xmm_index = _parse_xmm_operand(xmm_text)
    indexed = _parse_indexed_operand(mem_text.lower().replace("xmmword", ""))
    if xmm_index is None or indexed is None:
        return None
    base_slot, index_slot, shift, disp = indexed
    return (kind, xmm_index, base_slot, index_slot, shift, disp)


def _decode_fp_packed_arith_idx(text: str) -> tuple[str, str, int, int, int, int, int] | None:
    """Decode packed-FP arithmetic with a scaled-index source
    (``addpd xmm, [base+index*scale+disp]`` etc.) into
    ``("fppackedmemidx", mnemonic, xmm_index, base_slot, index_slot, shift, disp)``
    - vectorized accumulation over an array of vectors. Returns ``None`` otherwise.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in _FP_PACKED_ARITH:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    xmm_index = _parse_xmm_operand(left)
    if xmm_index is None:
        return None
    indexed = _parse_indexed_operand(right.lower().replace("xmmword", ""))
    if indexed is None:
        return None
    base_slot, index_slot, shift, disp = indexed
    return ("fppackedmemidx", mnemonic, xmm_index, base_slot, index_slot, shift, disp)


def _decode_fp_packed_riprel(text: str, insn_addr: int, insn_size: int) -> tuple[str, int, int] | None:
    """Decode a rip-relative packed 128-bit move (``movaps``/``movups`` etc.
    xmm <-> [rip+disp]) into ``("fpploadrip"|"fppstorerip", xmm_index,
    target_vaddr)``.

    SIMD constant vectors live in .rodata and are reached rip-relative. Returns
    ``None`` for a register, base+disp or indexed operand, or a non-packed-move
    mnemonic.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    if parts[0].lower() not in _FP_PACKED_MOVE:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None
    if left_mem:
        kind, mem_text, xmm_text = "fppstorerip", left, right
    else:
        kind, mem_text, xmm_text = "fpploadrip", right, left
    xmm_index = _parse_xmm_operand(xmm_text)
    # Drop the 128-bit size keyword so the shared rip-relative parser accepts it.
    parsed = _parse_riprel_operand(mem_text.lower().replace("xmmword", ""), insn_addr, insn_size)
    if xmm_index is None or parsed is None:
        return None
    target, _width = parsed
    return (kind, xmm_index, target)


def _decode_fp_packed_mem(text: str) -> tuple[str, int, int, int] | None:
    """Decode a packed 128-bit move with a ``[base+disp]`` memory operand
    (``movaps``/``movups``/``movapd``/``movupd`` xmm <-> [mem]) into
    ``("fppload"|"fppstore", xmm_index, base_slot, disp)``.

    Register-register packed moves are handled as full xmm copies elsewhere; a
    rip-relative or indexed packed operand stays native (deferred).
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    if parts[0].lower() not in _FP_PACKED_MOVE:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None
    if left_mem:
        kind, mem_text, xmm_text = "fppstore", left, right
    else:
        kind, mem_text, xmm_text = "fppload", right, left
    xmm_index = _parse_xmm_operand(xmm_text)
    # Drop the 128-bit size keyword so the shared base+disp parser accepts it.
    mem = _parse_mem_operand(mem_text.lower().replace("xmmword", ""))
    if xmm_index is None or mem is None:
        return None
    base_slot, disp, _width = mem
    return (kind, xmm_index, base_slot, disp)
