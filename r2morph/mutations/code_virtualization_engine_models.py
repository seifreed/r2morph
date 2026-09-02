"""Operand DTOs for the code-virtualization engine.

Each class is one decoded instruction destined for the VM bytecode. Pure
data (``__slots__`` + ``__init__``), no behaviour, no sibling dependency.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VirtualizedAddress:
    base_index: int
    disp: int
    index_index: int = 0
    scale: int = 0


class VirtualizedOp:
    """A single decoded instruction destined for the VM bytecode."""

    __slots__ = ("dst_index", "is_immediate", "mnemonic", "value", "width")

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

    __slots__ = ("base_index", "disp", "index_index", "kind", "reg_index", "scale", "width")

    def __init__(self, kind: str, reg_index: int, address: VirtualizedAddress, width: int) -> None:
        self.kind = kind
        self.reg_index = reg_index
        self.base_index = address.base_index
        self.disp = address.disp
        self.width = width
        # Only used by the ``*idx`` kinds: address = base + index*(2**scale) + disp.
        self.index_index = address.index_index
        self.scale = address.scale


class VirtualizedFpMemOp:
    """A scalar ``movsd``/``movss`` between an xmm register and ``[base+disp]``.

    ``kind`` is ``"fpload"`` (xmm <- [base+disp]) or ``"fpstore"`` ([base+disp] <-
    xmm). ``xmm_index`` is the 0-15 register number; ``base_index`` is the GP base
    register's context slot, read at runtime so the address is the program's real
    address (the interpreter spills registers but does not relocate the stack).
    ``width`` is 64 (movsd) or 32 (movss). The xmm value lives in the frame's xmm
    save area for the duration of the run and is reloaded into the architectural
    register on exit.
    """

    __slots__ = ("base_index", "disp", "index_index", "kind", "scale", "width", "xmm_index")

    def __init__(self, kind: str, xmm_index: int, address: VirtualizedAddress, width: int) -> None:
        self.kind = kind
        self.xmm_index = xmm_index
        self.base_index = address.base_index
        self.disp = address.disp
        self.width = width
        # Only used by the ``*idx`` kinds: address = base + index*(2**scale) + disp.
        self.index_index = address.index_index
        self.scale = address.scale


class VirtualizedFpArithOp:
    """A scalar reg-reg FP arithmetic op: ``{add,sub,mul,div}{sd,ss} xmm, xmm`` or
    ``sqrt{sd,ss} xmm, xmm``.

    ``op`` is one of add/sub/mul/div/sqrt; ``dst_index``/``src_index`` are 0-15 xmm
    register numbers; ``width`` is 64 (sd) or 32 (ss). Both operands and the result
    live in the frame's xmm save area for the run's duration. There is no MBA form
    for FP arithmetic, so the handler issues the real instruction; this is the only
    place FP is computed, never spelled out as the mnemonic in the bytecode.
    """

    __slots__ = ("dst_index", "op", "src_index", "width")

    def __init__(self, op: str, dst_index: int, src_index: int, width: int) -> None:
        self.op = op
        self.dst_index = dst_index
        self.src_index = src_index
        self.width = width


class VirtualizedFpScalarVexOp:
    """A three-operand VEX.128 scalar FP operation.

    The first source supplies the untouched upper lanes and the second source
    supplies the computed scalar. The interpreter clears the destination YMM
    upper half during its VEX epilogue.
    """

    __slots__ = ("dst_index", "mnemonic", "src1_index", "src2_index")

    def __init__(self, mnemonic: str, dst_index: int, src1_index: int, src2_index: int) -> None:
        self.mnemonic = mnemonic
        self.dst_index = dst_index
        self.src1_index = src1_index
        self.src2_index = src2_index


class VirtualizedFpConvertOp:
    """An int<->float conversion: ``cvtsi2{sd,ss} xmm, r`` or ``cvtt{sd,ss}2si r, xmm``.

    ``direction`` is ``"cvti2f"`` (int->float) or ``"cvtf2i"`` (float->int);
    ``fp_width`` is 64 (sd) or 32 (ss); ``gp_width`` is 32 or 64 (it changes the
    handler: a 32-bit conversion uses eax and saturates/truncates faithfully).
    The xmm value lives in the frame's xmm save area, the GP value in its slot.
    """

    __slots__ = ("direction", "fp_width", "gp_slot", "gp_width", "xmm_index")

    def __init__(self, direction: str, fp_width: int, gp_width: int, xmm_index: int, gp_slot: int) -> None:
        self.direction = direction
        self.fp_width = fp_width
        self.gp_width = gp_width
        self.xmm_index = xmm_index
        self.gp_slot = gp_slot


class VirtualizedFpArithMemOp:
    """Scalar reg-memory FP arithmetic: ``{add,sub,mul,div}{sd,ss} xmm, [base+disp]``.

    ``op`` is add/sub/mul/div; ``xmm_index`` is the destination (and first source)
    xmm; ``base_index`` is the GP base slot read at runtime for the real address;
    ``width`` is 64 (sd) or 32 (ss). The xmm operand lives in the frame's save area.
    """

    __slots__ = ("base_index", "disp", "index_index", "op", "scale", "width", "xmm_index")

    def __init__(self, op: str, xmm_index: int, address: VirtualizedAddress, width: int) -> None:
        self.op = op
        self.xmm_index = xmm_index
        # base_index < 0 marks the rip-relative form (disp carries the absolute
        # target); index_index >= 0 marks the scaled-index form (address =
        # base + index*(2**scale) + disp).
        self.base_index = address.base_index
        self.disp = address.disp
        self.width = width
        self.index_index = address.index_index
        self.scale = address.scale


class VirtualizedFpPackedOp:
    """A packed 128-bit reg-reg SIMD op, including VEX.128 lowering.

    ``mnemonic`` is the legacy SSE spelling used by the handler (for example
    ``addpd`` or ``xorps``). ``vex`` records that the original instruction had
    VEX.128 zero-upper semantics; the epilogue clears the destination's YMM upper
    half after restoring its lower 128 bits. ``src1_index`` is populated only for
    a non-destructive VEX instruction whose first source differs from the
    destination; legacy SSE and destructive VEX forms leave it unset.
    """

    __slots__ = ("dst_index", "mnemonic", "src1_index", "src_index", "vex")

    def __init__(
        self,
        mnemonic: str,
        dst_index: int,
        src_index: int,
        vex: bool = False,
        src1_index: int | None = None,
    ) -> None:
        self.mnemonic = mnemonic
        self.dst_index = dst_index
        self.src_index = src_index
        self.vex = vex
        self.src1_index = src1_index


class VirtualizedFpPackedImmediateOp:
    """A legacy 128-bit packed integer shift with an immediate count."""

    __slots__ = ("dst_index", "immediate", "mnemonic")

    def __init__(self, mnemonic: str, dst_index: int, immediate: int) -> None:
        self.mnemonic = mnemonic
        self.dst_index = dst_index
        self.immediate = immediate


class VirtualizedFpPackedMemOp:
    """A packed 128-bit move between an xmm register and indexed memory.

    ``kind`` is ``"fppload"``/``"fppstore"`` for ``[base+disp]`` or the corresponding
    ``idx``/``idxnb`` form for scaled-index addressing. The full 128 bits move via
    movups (no alignment assumption). ``base_index`` is the GP base slot, or ``-1``
    for the no-base form; ``index_index`` and ``scale`` describe the scaled index.
    """

    __slots__ = ("base_index", "disp", "index_index", "kind", "scale", "xmm_index")

    def __init__(self, kind: str, xmm_index: int, address: VirtualizedAddress) -> None:
        self.kind = kind
        self.xmm_index = xmm_index
        self.base_index = address.base_index
        self.disp = address.disp
        self.index_index = address.index_index
        self.scale = address.scale
