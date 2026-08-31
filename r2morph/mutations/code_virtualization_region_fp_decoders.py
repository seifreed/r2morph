"""Floating-point and SIMD instruction decoders for region virtualization."""

from __future__ import annotations

from typing import Any

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

_DWORD_WIDTH_BITS = 32
_QWORD_WIDTH_BITS = 64
_PACKED_VEX_OPERAND_COUNT = 3
_PACKED_VEX_MOVE_OPERAND_COUNT = 2
_PACKED_OPERAND_COUNT = 2
_PACKED_SHIFT_IMMEDIATE_COUNT = 3
_PACKED_IMMEDIATE_MAX = 0xFF


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


def _parse_ymm_operand(text: str) -> int | None:
    """Parse ``ymmN`` (0-15) into its register index, or ``None``."""
    text = text.strip().lower()
    if not text.startswith("ymm"):
        return None
    try:
        index = int(text[3:])
    except ValueError:
        return None
    return index if 0 <= index < _REGISTER_COUNT else None


def _decode_fp_mem(text: str) -> tuple[str, int, int, int, int] | None:
    """Decode ``movsd/movss/movq xmm, [base+disp]`` or the store form.

    Returns ``(kind, xmm_index, base_slot, disp, width)`` where ``kind`` is
    ``"fpload"`` or ``"fpstore"`` and ``width`` is 64 (movsd/movq) or 32 (movss), or
    ``None`` for xmm-to-xmm moves, indexed/rip-relative addressing, or any other
    form. Only reached for ``family == "vec"`` instructions, so the no-operand
    string ``movsd`` never lands here.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    width = {"movsd": 64, "movss": 32, "movq": 64}.get(parts[0].lower())
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
    "sqrtsd": ("sqrt", 64),
    "minsd": ("min", 64),
    "maxsd": ("max", 64),
    "addss": ("add", 32),
    "subss": ("sub", 32),
    "mulss": ("mul", 32),
    "divss": ("div", 32),
    "sqrtss": ("sqrt", 32),
    "minss": ("min", 32),
    "maxss": ("max", 32),
}


def _decode_fp_arith(text: str) -> tuple[str, str, int, int, int] | None:
    """Decode scalar-FP register-register arithmetic
    (``addsd/subsd/mulsd/divsd/sqrtsd/minsd/maxsd`` and ``ss`` forms).

    Returns ``(kind, op, dst_index, src_index, width)`` with ``kind == "fparith"``,
    ``op`` one of add/sub/mul/div/sqrt/min/max, or ``None`` for a memory source (left native)
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


def _decode_fp_gp_move(text: str, mnemonic: str, kind: str, width: int) -> tuple[str, str, int, int] | None:
    """Decode an integer transfer between a GP and XMM register.

    ``movd`` and ``movq`` use the same bytecode shape while their handlers
    preserve the instruction-specific width and zeroing semantics.
    Stack-pointer operands remain native because the region VM reserves that
    register for its relocated program stack.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != mnemonic or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    left_xmm = _parse_xmm_operand(left)
    right_xmm = _parse_xmm_operand(right)
    if left_xmm is not None:
        gp = _register_operand(right)
        if gp is None or gp[1] != width:
            return None
        direction, xmm_index = "gp_to_xmm", left_xmm
    elif right_xmm is not None:
        gp = _register_operand(left)
        if gp is None or gp[1] != width:
            return None
        direction, xmm_index = "xmm_to_gp", right_xmm
    else:
        return None
    return (kind, direction, xmm_index, gp[0])


def _decode_fp_movd(text: str) -> tuple[str, str, int, int] | None:
    """Decode a 32-bit integer transfer between a GP and XMM register."""
    return _decode_fp_gp_move(text, "movd", "fpmovd", _DWORD_WIDTH_BITS)


def _decode_fp_movq(text: str) -> tuple[str, str, int, int] | None:
    """Decode a 64-bit integer transfer between a GP and XMM register."""
    return _decode_fp_gp_move(text, "movq", "fpmovq", _QWORD_WIDTH_BITS)


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


def _decode_fp_compare_idx(text: str) -> tuple[str, str, int, int, int, int, int, int] | None:
    """Decode scalar-FP compare with a scaled-index memory source."""
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
    indexed = _parse_indexed_operand(right, base_optional=True)
    if xmm_index is None or indexed is None:
        return None
    base_slot, index_slot, shift, displacement = indexed
    kind = "fpcmpmemidxnb" if base_slot < 0 else "fpcmpmemidx"
    return (kind, mnemonic, xmm_index, base_slot, index_slot, shift, displacement, width)


# Full 128-bit xmm-xmm copies vs scalar copies that preserve the destination's
# upper lane(s). (movsd/movss xmm,xmm preserve the high lanes, unlike the memory
# load forms which zero them - so they get the "sd"/"ss" preserving handler.
# movq xmm,xmm copies the low qword and clears the high qword.)
_FP_MOVE_FULL: frozenset[str] = frozenset({"movaps", "movapd", "movups", "movupd", "movdqa", "movdqu"})
_FP_MOVE_SCALAR: dict[str, str] = {"movsd": "sd", "movss": "ss", "movq": "q"}


def _decode_fp_move(text: str) -> tuple[str, str, int, int] | None:
    """Decode a register-register xmm move into ``("fpmov", mode, dst, src)``.

    ``mode`` is ``"full"`` (movaps/movapd/movups/movupd, full 128-bit copy) or
    ``"sd"``/``"ss"`` (movsd/movss, low element copied, destination upper lanes
    preserved) or ``"q"`` (movq, low qword copied and upper qword cleared).
    Returns ``None`` for a memory operand (handled as load/store) or any other
    non-move mnemonic.
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
    """Decode ``movsd/movss/movq xmm, [rip+disp]`` or the store form into
    ``("fploadrip"|"fpstorerip", xmm_index, target_vaddr, width)``.

    FP constants and globals live in .rodata/.data and are reached rip-relative;
    the absolute target is later re-expressed relative to the bytecode base.
    Returns ``None`` for a register or base+disp operand (other paths) or any
    non-movsd/movss/movq mnemonic.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    width = {"movsd": 64, "movss": 32, "movq": 64}.get(parts[0].lower())
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
    """Decode ``movsd/movss/movq xmm, [base+index*scale+disp]`` or the store form.
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
    width = {"movsd": 64, "movss": 32, "movq": 64}.get(parts[0].lower())
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
    indexed = _parse_indexed_operand(right, base_optional=True)
    if xmm_index is None or indexed is None:
        return None
    base_slot, index_slot, shift, disp = indexed
    kind = "fparithmemidxnb" if base_slot < 0 else "fparithmemidx"
    return (kind, op, xmm_index, base_slot, index_slot, shift, disp, width)


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
        "sqrtpd",
        "sqrtps",
        "minpd",
        "minps",
        "maxpd",
        "maxps",
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
        "psllw",
        "psllq",
        "psrlw",
        "psrlq",
        "psraw",
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
    }
)
_FP_PACKED_IMMEDIATE: frozenset[str] = frozenset(
    {"psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq", "psraw", "psrad", "pshufd"}
)
_FP_PACKED_MOVE: frozenset[str] = frozenset({"movaps", "movups", "movapd", "movupd", "movdqa", "movdqu"})
_FP_VEX_PACKED_ARITH: dict[str, str] = {
    "vaddps": "addps",
    "vaddpd": "addpd",
    "vsubps": "subps",
    "vsubpd": "subpd",
    "vmulps": "mulps",
    "vmulpd": "mulpd",
    "vdivps": "divps",
    "vdivpd": "divpd",
    "vminps": "minps",
    "vminpd": "minpd",
    "vmaxps": "maxps",
    "vmaxpd": "maxpd",
    "vandps": "andps",
    "vandpd": "andpd",
    "vorps": "orps",
    "vorpd": "orpd",
    "vxorps": "xorps",
    "vxorpd": "xorpd",
    "vpand": "pand",
    "vpandn": "pandn",
    "vpor": "por",
    "vpxor": "pxor",
    "vpaddd": "paddd",
    "vpsubd": "psubd",
    "vpaddb": "paddb",
    "vpsubb": "psubb",
    "vpaddw": "paddw",
    "vpsubw": "psubw",
    "vpaddq": "paddq",
    "vpsubq": "psubq",
    "vpslld": "pslld",
    "vpsrld": "psrld",
    "vpsrad": "psrad",
    "vpsllw": "psllw",
    "vpsllq": "psllq",
    "vpsrlw": "psrlw",
    "vpsrlq": "psrlq",
    "vpsraw": "psraw",
    "vpshufd": "pshufd",
    "vpmulld": "pmulld",
    "vpminsd": "pminsd",
    "vpmaxsd": "pmaxsd",
    "vpcmpeqd": "pcmpeqd",
    "vpcmpgtd": "pcmpgtd",
    "vpaddusb": "paddusb",
    "vpsubusb": "psubusb",
    "vpaddusw": "paddusw",
    "vpsubusw": "psubusw",
    "vpavgb": "pavgb",
    "vpavgw": "pavgw",
    "vpsadbw": "psadbw",
    "vpmaddwd": "pmaddwd",
    "vpmulhuw": "pmulhuw",
    "vpmulhw": "pmulhw",
    "vpackuswb": "packuswb",
    "vpackssdw": "packssdw",
    "vpunpcklbw": "punpcklbw",
    "vpunpcklwd": "punpcklwd",
}
_FP_VEX_PACKED_UNARY_ARITH: dict[str, str] = {"vsqrtps": "sqrtps", "vsqrtpd": "sqrtpd"}
_FP_VEX_PACKED_MOVE: frozenset[str] = frozenset({"vmovaps", "vmovups", "vmovapd", "vmovupd", "vmovdqa", "vmovdqu"})
_FP_VEX_SCALAR_ARITH: dict[str, tuple[str, int]] = {
    "vaddss": ("add", 32),
    "vsubss": ("sub", 32),
    "vmulss": ("mul", 32),
    "vdivss": ("div", 32),
    "vsqrtss": ("sqrt", 32),
    "vminss": ("min", 32),
    "vmaxss": ("max", 32),
    "vaddsd": ("add", 64),
    "vsubsd": ("sub", 64),
    "vmulsd": ("mul", 64),
    "vdivsd": ("div", 64),
    "vsqrtsd": ("sqrt", 64),
    "vminsd": ("min", 64),
    "vmaxsd": ("max", 64),
}
_FP_VEX_SCALAR_MOVE: dict[str, int] = {"vmovq": 64, "vmovss": 32, "vmovsd": 64}


def _decode_fp_packed_immediate(text: str) -> tuple[str, str, int, int] | None:
    """Decode a legacy packed integer operation with an immediate byte."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in _FP_PACKED_IMMEDIATE:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _PACKED_OPERAND_COUNT:
        return None
    destination = _parse_xmm_operand(operands[0])
    if destination is None:
        return None
    try:
        immediate = int(operands[1], 0)
    except ValueError:
        return None
    return ("fppackedimm", mnemonic, destination, immediate) if 0 <= immediate <= _PACKED_IMMEDIATE_MAX else None


def _decode_fp_vex_packed_immediate(text: str) -> tuple[str, str, int, int, int] | None:
    """Decode VEX packed integer operations whose control byte is immediate."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    mnemonic = parts[0].lower()
    operation = _FP_VEX_PACKED_ARITH.get(mnemonic)
    if len(parts) != _INSTRUCTION_PART_COUNT or operation not in _FP_PACKED_IMMEDIATE:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _PACKED_SHIFT_IMMEDIATE_COUNT:
        return None
    register_parser = _parse_ymm_operand if operands[0].lower().startswith("ymm") else _parse_xmm_operand
    destination = register_parser(operands[0])
    source = register_parser(operands[1])
    if destination is None or source is None:
        return None
    try:
        immediate = int(operands[2], 0)
    except ValueError:
        return None
    kind = "fppackedvex256imm" if operands[0].lower().startswith("ymm") else "fppackedveximm"
    return (kind, operation, destination, source, immediate) if 0 <= immediate <= _PACKED_IMMEDIATE_MAX else None


def _decode_fp_vex_scalar_arith(text: str) -> tuple[str, str, int, int, int, int] | None:
    """Decode three-operand VEX.128 scalar FP arithmetic."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    spec = _FP_VEX_SCALAR_ARITH.get(parts[0].lower())
    if spec is None:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _PACKED_VEX_OPERAND_COUNT:
        return None
    registers = tuple(_parse_xmm_operand(operand) for operand in operands)
    destination, first_source, second_source = registers
    if destination is None or first_source is None or second_source is None:
        return None
    operation, width = spec
    return ("fparithvex", operation, destination, first_source, second_source, width)


def _vex_scalar_memory_item(
    operation: tuple[str, int, int | None],
    memory: str,
    width: int,
    instruction: tuple[int, int],
) -> tuple[Any, ...] | None:
    kind, destination, source = operation
    insn_addr, insn_size = instruction
    result: tuple[Any, ...] | None = None
    explicit_width = {"dword": 32, "qword": 64}.get(memory.lower().split(None, 1)[0])
    if explicit_width is None or explicit_width == width:
        indexed = _parse_indexed_operand(memory, base_optional=True)
        if indexed is not None:
            base_slot, index_slot, shift, displacement = indexed
            if base_slot < 0:
                result = (kind + "idxnb", destination, index_slot, shift, displacement, width)
            else:
                result = (kind + "idx", destination, base_slot, index_slot, shift, displacement, width)
        else:
            rip_relative = _parse_riprel_operand(memory, insn_addr, insn_size)
            if rip_relative is not None:
                target, memory_width = rip_relative
                if memory_width is None or memory_width == width:
                    result = (kind + "rip", destination, target, width)
            else:
                parsed_memory = _parse_mem_operand(memory)
                if parsed_memory is not None:
                    base_slot, displacement, memory_width = parsed_memory
                    if memory_width is None or memory_width == width:
                        result = (kind, destination, base_slot, displacement, width)
    if result is not None and source is not None:
        result = (result[0], result[1], source, *result[2:])
    return result


def _decode_fp_vex_scalar_move_pair(
    operands: list[str], width: int, instruction: tuple[int, int]
) -> tuple[Any, ...] | None:
    destination = _parse_xmm_operand(operands[0])
    source = _parse_xmm_operand(operands[1])
    if destination is not None and source is not None:
        return ("fpmovvexscalar", width, destination, source)
    left_mem, right_mem = "[" in operands[0], "[" in operands[1]
    if left_mem == right_mem:
        return None
    if left_mem:
        if source is None:
            return None
        return _vex_scalar_memory_item(("fpstorevex", source, None), operands[0], width, instruction)
    if destination is None:
        return None
    return _vex_scalar_memory_item(("fploadvex", destination, None), operands[1], width, instruction)


def _decode_fp_vex_scalar_move_triple(
    operands: list[str], width: int, instruction: tuple[int, int]
) -> tuple[Any, ...] | None:
    destination = _parse_xmm_operand(operands[0])
    first_source = _parse_xmm_operand(operands[1])
    if destination is None or first_source is None:
        return None
    second_source = _parse_xmm_operand(operands[2])
    if second_source is not None:
        return ("fpmovvexscalar3", width, destination, first_source, second_source)
    if "[" not in operands[2]:
        return None
    return _vex_scalar_memory_item(("fpmovvexmem", destination, first_source), operands[2], width, instruction)


def _decode_fp_vex_gp_move(text: str) -> tuple[str, str, int, int] | None:
    """Decode VEX.128 ``vmovd``/``vmovq`` transfers between XMM and GP registers."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    spec = {"vmovd": ("fpmovvexgpd", _DWORD_WIDTH_BITS), "vmovq": ("fpmovvexgp", _QWORD_WIDTH_BITS)}.get(
        parts[0].lower()
    )
    if spec is None:
        return None
    kind, width = spec
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    left_xmm = _parse_xmm_operand(left)
    right_xmm = _parse_xmm_operand(right)
    if left_xmm is not None:
        gp = _register_operand(right)
        if gp is None or gp[1] != width:
            return None
        direction, xmm_index = "gp_to_xmm", left_xmm
    elif right_xmm is not None:
        gp = _register_operand(left)
        if gp is None or gp[1] != width:
            return None
        direction, xmm_index = "xmm_to_gp", right_xmm
    else:
        return None
    return (kind, direction, xmm_index, gp[0])


def _decode_fp_vex_scalar_move(text: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode VEX scalar moves in register and memory forms.

    Two-operand moves zero the unused low-XMM lanes. Three-operand moves copy
    the upper lanes from the first source and the scalar from the second.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    width = _FP_VEX_SCALAR_MOVE.get(parts[0].lower())
    if width is None:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    instruction = (insn_addr, insn_size)
    if len(operands) == _PACKED_VEX_MOVE_OPERAND_COUNT:
        return _decode_fp_vex_scalar_move_pair(operands, width, instruction)
    if len(operands) == _PACKED_VEX_OPERAND_COUNT:
        return _decode_fp_vex_scalar_move_triple(operands, width, instruction)
    return None


def _parse_fp_vex_scalar_memory_operands(text: str) -> tuple[str, int, int, int, str] | None:
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    spec = _FP_VEX_SCALAR_ARITH.get(parts[0].lower())
    if spec is None:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _PACKED_VEX_OPERAND_COUNT or "[" not in operands[2]:
        return None
    destination = _parse_xmm_operand(operands[0])
    first_source = _parse_xmm_operand(operands[1])
    if destination is None or first_source is None:
        return None
    operation, width = spec
    return operation, width, destination, first_source, operands[2]


def _decode_fp_vex_scalar_arith_mem(text: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode VEX scalar arithmetic with a memory third operand.

    The first source is retained because VEX scalar instructions copy its upper
    lanes, unlike the legacy two-operand SSE form.
    """
    parsed_operands = _parse_fp_vex_scalar_memory_operands(text)
    if parsed_operands is None:
        return None
    operation, width, destination, first_source, memory = parsed_operands
    memory_head = memory.lower().split(None, 1)[0]
    explicit_width = {"dword": _DWORD_WIDTH_BITS, "qword": 64}.get(memory_head)
    result: tuple[Any, ...] | None = None
    if explicit_width is None or explicit_width == width:
        indexed = _parse_indexed_operand(memory, base_optional=True)
        if indexed is not None:
            base_slot, index_slot, shift, displacement = indexed
            kind = "fparithvexmemidxnb" if base_slot < 0 else "fparithvexmemidx"
            result = (
                (kind, operation, destination, first_source, index_slot, shift, displacement, width)
                if base_slot < 0
                else (kind, operation, destination, first_source, base_slot, index_slot, shift, displacement, width)
            )
        else:
            rip_relative = _parse_riprel_operand(memory, insn_addr, insn_size)
            if rip_relative is not None:
                target, memory_width = rip_relative
                if memory_width is None or memory_width == width:
                    result = ("fparithvexmemrip", operation, destination, first_source, target, width)
            else:
                parsed_memory = _parse_mem_operand(memory)
                if parsed_memory is not None:
                    base_slot, displacement, memory_width = parsed_memory
                    if memory_width is None or memory_width == width:
                        result = ("fparithvexmem", operation, destination, first_source, base_slot, displacement, width)
    return result


def _decode_fp_vex_packed_arith(text: str) -> tuple[str, str, int, int, int] | None:
    """Decode VEX.128 packed FP arithmetic, including unary square roots."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    mnemonic = parts[0].lower()
    if mnemonic in _FP_VEX_PACKED_UNARY_ARITH:
        return _decode_fp_vex_packed_unary_arith(text)
    if mnemonic not in _FP_VEX_PACKED_ARITH:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _PACKED_VEX_OPERAND_COUNT:
        return None
    registers = tuple(_parse_xmm_operand(operand) for operand in operands)
    destination, first_source, second_source = registers
    if destination is None or first_source is None or second_source is None:
        return None
    return (
        "fppackedvex",
        _FP_VEX_PACKED_ARITH[mnemonic],
        destination,
        first_source,
        second_source,
    )


def _decode_fp_vex_packed_unary_arith(text: str) -> tuple[str, str, int, int, int] | None:
    """Encode a unary VEX.128 operation in the shared packed handler shape."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    operation = _FP_VEX_PACKED_UNARY_ARITH.get(parts[0].lower())
    if operation is None:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _PACKED_VEX_MOVE_OPERAND_COUNT:
        return None
    destination, source = (_parse_xmm_operand(operand) for operand in operands)
    if destination is None or source is None:
        return None
    return ("fppackedvex", operation, destination, destination, source)


def _decode_fp_vex_packed_move(text: str) -> tuple[str, str, int, int] | None:
    """Decode a register-register VEX.128 packed move."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() not in _FP_VEX_PACKED_MOVE:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _PACKED_VEX_MOVE_OPERAND_COUNT:
        return None
    destination, source = (_parse_xmm_operand(operand) for operand in operands)
    if destination is None or source is None:
        return None
    return ("fpmovvex", "full", destination, source)


def _parse_ymm_operands(text: str, count: int) -> tuple[int, ...] | None:
    operands = [token.strip() for token in text.split(",")]
    if len(operands) != count:
        return None
    parsed = tuple(_parse_ymm_operand(operand) for operand in operands)
    indices: list[int] = []
    for value in parsed:
        if value is None:
            return None
        indices.append(value)
    return tuple(indices)


def _decode_fp_vex_256_packed_arith(text: str) -> tuple[str, str, int, int, int] | None:
    """Decode packed VEX.256 arithmetic into a dedicated 256-bit item shape."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    mnemonic = parts[0].lower()
    if mnemonic in _FP_VEX_PACKED_UNARY_ARITH:
        unary_operation = _FP_VEX_PACKED_UNARY_ARITH[mnemonic]
        parsed = _parse_ymm_operands(parts[1], _PACKED_VEX_MOVE_OPERAND_COUNT)
        if parsed is None:
            return None
        destination, source = parsed
        return ("fppackedvex256", unary_operation, destination, destination, source)
    binary_operation = _FP_VEX_PACKED_ARITH.get(mnemonic)
    parsed = _parse_ymm_operands(parts[1], _PACKED_VEX_OPERAND_COUNT)
    if binary_operation is None or parsed is None:
        return None
    destination, first_source, second_source = parsed
    return ("fppackedvex256", binary_operation, destination, first_source, second_source)


def _decode_fp_vex_256_packed_arith_mem(
    text: str, insn_addr: int, insn_size: int
) -> (
    tuple[str, str, int, int, int, int]
    | tuple[str, str, int, int, int]
    | tuple[str, str, int, int, int, int, int, int]
    | tuple[str, str, int, int, int, int, int]
    | None
):
    """Decode a VEX.256 packed arithmetic operation with a memory source."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    mnemonic = parts[0].lower()
    binary_operation = _FP_VEX_PACKED_ARITH.get(mnemonic)
    unary_operation = _FP_VEX_PACKED_UNARY_ARITH.get(mnemonic)
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) not in (_PACKED_VEX_MOVE_OPERAND_COUNT, _PACKED_VEX_OPERAND_COUNT):
        return None
    is_unary = len(operands) == _PACKED_VEX_MOVE_OPERAND_COUNT
    operation = unary_operation if is_unary else binary_operation
    if operation is None or "[" not in operands[-1]:
        return None
    destination = _parse_ymm_operand(operands[0])
    first_source = destination if is_unary else _parse_ymm_operand(operands[1])
    if destination is None or first_source is None:
        return None
    memory = operands[-1].lower().replace("ymmword", "")
    result: (
        tuple[str, str, int, int, int, int]
        | tuple[str, str, int, int, int]
        | tuple[str, str, int, int, int, int, int, int]
        | tuple[str, str, int, int, int, int, int]
    )
    indexed = _parse_indexed_operand(memory, base_optional=True)
    if indexed is not None:
        base_slot, index_slot, shift, displacement = indexed
        if base_slot < 0:
            result = ("fppackedvex256memidxnb", operation, destination, first_source, index_slot, shift, displacement)
        else:
            result = (
                "fppackedvex256memidx",
                operation,
                destination,
                first_source,
                base_slot,
                index_slot,
                shift,
                displacement,
            )
    else:
        rip_relative = _parse_riprel_operand(memory, insn_addr, insn_size)
        if rip_relative is not None:
            result = ("fppackedvex256memrip", operation, destination, first_source, rip_relative[0])
        else:
            parsed_memory = _parse_mem_operand(memory)
            if parsed_memory is None:
                return None
            base_slot, displacement, _width = parsed_memory
            result = ("fppackedvex256mem", operation, destination, first_source, base_slot, displacement)
    return result


def _decode_fp_vex_packed_arith_mem(
    text: str, insn_addr: int, insn_size: int
) -> (
    tuple[str, str, int, int, int, int]
    | tuple[str, str, int, int, int]
    | tuple[str, str, int, int, int, int, int, int]
    | tuple[str, str, int, int, int, int, int]
    | None
):
    """Decode a VEX.128 packed arithmetic operation with a memory source."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    mnemonic = parts[0].lower()
    binary_operation = _FP_VEX_PACKED_ARITH.get(mnemonic)
    unary_operation = _FP_VEX_PACKED_UNARY_ARITH.get(mnemonic)
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) not in (_PACKED_VEX_MOVE_OPERAND_COUNT, _PACKED_VEX_OPERAND_COUNT):
        return None
    is_unary = len(operands) == _PACKED_VEX_MOVE_OPERAND_COUNT
    operation = unary_operation if is_unary else binary_operation
    if operation is None or "[" not in operands[-1]:
        return None
    destination = _parse_xmm_operand(operands[0])
    first_source = destination if is_unary else _parse_xmm_operand(operands[1])
    if destination is None or first_source is None:
        return None
    memory = operands[-1].lower().replace("xmmword", "")
    result: (
        tuple[str, str, int, int, int, int]
        | tuple[str, str, int, int, int]
        | tuple[str, str, int, int, int, int, int, int]
        | tuple[str, str, int, int, int, int, int]
        | None
    ) = None
    indexed = _parse_indexed_operand(memory, base_optional=True)
    if indexed is not None:
        base_slot, index_slot, shift, displacement = indexed
        if base_slot < 0:
            result = ("fppackedvexmemidxnb", operation, destination, first_source, index_slot, shift, displacement)
        else:
            result = (
                "fppackedvexmemidx",
                operation,
                destination,
                first_source,
                base_slot,
                index_slot,
                shift,
                displacement,
            )
    else:
        rip_relative = _parse_riprel_operand(memory, insn_addr, insn_size)
        if rip_relative is not None:
            result = ("fppackedvexmemrip", operation, destination, first_source, rip_relative[0])
        else:
            parsed_memory = _parse_mem_operand(memory)
            if parsed_memory is not None:
                base_slot, displacement, _width = parsed_memory
                result = ("fppackedvexmem", operation, destination, first_source, base_slot, displacement)
    return result


def _decode_fp_vex_256_packed_move(text: str) -> tuple[str, str, int, int] | None:
    """Decode a register-register VEX.256 packed move."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() not in _FP_VEX_PACKED_MOVE:
        return None
    operands = [token.strip() for token in parts[1].split(",")]
    if len(operands) != _PACKED_VEX_MOVE_OPERAND_COUNT:
        return None
    destination, source = (_parse_ymm_operand(operand) for operand in operands)
    if destination is None or source is None:
        return None
    return ("fpmovvex256", "full", destination, source)


def _decode_fp_vex_256_packed_mem(
    text: str, insn_addr: int, insn_size: int
) -> (
    tuple[str, int, int, int]
    | tuple[str, int, int]
    | tuple[str, int, int, int, int]
    | tuple[str, int, int, int, int, int]
    | None
):
    """Decode a VEX.256 packed move between a YMM register and memory."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() not in _FP_VEX_PACKED_MOVE:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None
    if left_mem:
        kind, mem_text, ymm_text = "fpstorevex256", left, right
    else:
        kind, mem_text, ymm_text = "fploadvex256", right, left
    ymm_index = _parse_ymm_operand(ymm_text)
    if ymm_index is None:
        return None
    normalized_mem = mem_text.lower().replace("ymmword", "")
    result: (
        tuple[str, int, int, int]
        | tuple[str, int, int]
        | tuple[str, int, int, int, int]
        | tuple[str, int, int, int, int, int]
        | None
    ) = None
    indexed = _parse_indexed_operand(normalized_mem, base_optional=True)
    if indexed is not None:
        base_slot, index_slot, shift, displacement = indexed
        if base_slot < 0:
            result = (kind + "idxnb", ymm_index, index_slot, shift, displacement)
        else:
            result = (kind + "idx", ymm_index, base_slot, index_slot, shift, displacement)
    else:
        parsed_rip = _parse_riprel_operand(normalized_mem, insn_addr, insn_size)
        if parsed_rip is not None:
            result = (kind + "rip", ymm_index, parsed_rip[0])
        else:
            memory = _parse_mem_operand(normalized_mem)
            if memory is not None:
                base_slot, displacement, _width = memory
                result = (kind, ymm_index, base_slot, displacement)
    return result


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


def _decode_fp_packed_indexed(
    text: str,
) -> tuple[str, int, int, int, int, int] | tuple[str, int, int, int, int] | None:
    """Decode a scaled-index packed 128-bit move (``movaps``/``movups`` etc.
    xmm <-> [base+index*scale+disp]) into ``("fpploadidx"|"fppstoreidx",
    xmm_index, base_slot, index_slot, shift, disp)`` - access into an array of
    vectors. The no-base form uses an ``nb`` suffix and omits ``base_slot``.
    Returns ``None`` for a register, base+disp or rip-relative operand.
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
    indexed = _parse_indexed_operand(mem_text.lower().replace("xmmword", ""), base_optional=True)
    if xmm_index is None or indexed is None:
        return None
    base_slot, index_slot, shift, disp = indexed
    if base_slot < 0:
        return (kind + "nb", xmm_index, index_slot, shift, disp)
    return (kind, xmm_index, base_slot, index_slot, shift, disp)


def _decode_fp_packed_arith_idx(
    text: str,
) -> tuple[str, str, int, int, int, int, int] | tuple[str, str, int, int, int, int] | None:
    """Decode packed-FP arithmetic with a scaled-index source
    (``addpd xmm, [base+index*scale+disp]`` etc.) into
    ``("fppackedmemidx", mnemonic, xmm_index, base_slot, index_slot, shift, disp)``
    - vectorized accumulation over an array of vectors. The no-base form uses an
    ``nb`` suffix and omits ``base_slot``. Returns ``None`` otherwise.
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
    indexed = _parse_indexed_operand(right.lower().replace("xmmword", ""), base_optional=True)
    if indexed is None:
        return None
    base_slot, index_slot, shift, disp = indexed
    if base_slot < 0:
        return ("fppackedmemidxnb", mnemonic, xmm_index, index_slot, shift, disp)
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
