"""Memory and addressing instruction decoders for region virtualization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from r2morph.mutations.code_virtualization_engine import (
    REGISTER32_INDEX,
    REGISTER_INDEX,
    immediate_fits_width,
)
from r2morph.mutations.code_virtualization_region_decoders import (
    _BYTE_WIDTH_BITS,
    _INSTRUCTION_PART_COUNT,
    _MOVX_SRC_SIZES,
    _QWORD_WIDTH_BITS,
    _WORD_WIDTH_BITS,
    REGISTER8_INDEX,
    REGISTER16_INDEX,
    _memory_register_operand,
    _parse_mem_operand,
    _parse_tls_operand,
    _register_operand,
)

_DWORD_WIDTH_BITS = 32
_BYTE_IMMEDIATE_MAX = 0xFF
_LOCKED_INSTRUCTION_PART_COUNT = 3
_INDEXED_MEMORY_WIDTHS = {
    "byte": _BYTE_WIDTH_BITS,
    "word": _WORD_WIDTH_BITS,
    "dword": _DWORD_WIDTH_BITS,
    "qword": _QWORD_WIDTH_BITS,
}


def _parse_tls_indexed_operand(text: str) -> tuple[str, int, int, int, int, int | None] | None:
    """Parse an FS/GS operand with a scaled index and optional base."""
    text = text.strip().lower()
    width: int | None = None
    head = text.split(None, 1)
    if head and head[0] in _INDEXED_MEMORY_WIDTHS:
        width = _INDEXED_MEMORY_WIDTHS[head[0]]
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
    indexed = _parse_indexed_operand(f"[{expression}]", base_optional=True)
    if indexed is None:
        return None
    base, index, shift, displacement = indexed
    return segment, base, index, shift, displacement, width


def _decode_tls_indexed_memory_mov(left: str, right: str) -> tuple[Any, ...] | None:
    left_indexed = _parse_tls_indexed_operand(left)
    right_indexed = _parse_tls_indexed_operand(right)
    if left_indexed is not None and right_indexed is None:
        kind, memory, register_text = "tlsstoreidx", left_indexed, right
    elif right_indexed is not None and left_indexed is None:
        kind, memory, register_text = "tlsloadidx", right_indexed, left
    else:
        return None
    register = _memory_register_operand(register_text.lower())
    if register is None:
        return None
    segment, base_slot, index_slot, shift, displacement, memory_width = memory
    register_slot, register_width = register
    if memory_width is not None and memory_width != register_width:
        return None
    if base_slot < 0:
        kind += "nb"
    return (kind, register_slot, segment, base_slot, index_slot, shift, displacement, register_width)


def _decode_tls_memory_mov(text: str) -> tuple[Any, ...] | None:
    """Decode GP loads/stores through the current thread's FS/GS base."""
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "mov" or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    indexed = _decode_tls_indexed_memory_mov(left, right)
    if indexed is not None:
        return indexed
    left_tls, right_tls = _parse_tls_operand(left), _parse_tls_operand(right)
    if left_tls is not None and right_tls is None:
        kind, memory, register_text = "tlsstore", left_tls, right
    elif right_tls is not None and left_tls is None:
        kind, memory, register_text = "tlsload", right_tls, left
    else:
        return None
    register = _memory_register_operand(register_text.lower())
    if register is None:
        return None
    segment, base_slot, displacement, memory_width = memory
    register_slot, register_width = register
    if memory_width is not None and memory_width != register_width:
        return None
    return kind, register_slot, segment, base_slot, displacement, register_width


def _decode_memory_mov(text: str) -> tuple[str, int, int, int, int] | None:
    """Decode ``mov reg, [base+disp]`` / ``mov [base+disp], reg``.

    Returns ``(kind, reg_slot, base_slot, disp, width)`` where ``kind`` is
    ``"load"`` or ``"store"``, or ``None`` for unsupported operands.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "mov" or "," not in parts[1]:
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
    reg = _memory_register_operand(reg_text.lower())
    if mem is None or reg is None:
        return None
    base_slot, disp, mem_width = mem
    reg_slot, reg_width = reg
    if mem_width is not None and mem_width != reg_width:
        return None
    return (kind, reg_slot, base_slot, disp, reg_width)


def _decode_memory_immediate(text: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode ``mov [address], immediate`` for direct, RIP-relative, and indexed addresses."""
    parts = text.split(None, 1)
    result: tuple[Any, ...] | None = None
    if len(parts) == _INSTRUCTION_PART_COUNT and parts[0].lower() == "mov" and "," in parts[1]:
        memory_text, immediate_text = (token.strip() for token in parts[1].split(",", 1))
        if "[" in memory_text and "[" not in immediate_text:
            direct = _parse_mem_operand(memory_text)
            if direct is not None:
                base_slot, displacement, width = direct
                if width is not None:
                    result = _memory_immediate_item("storei", immediate_text, width, (base_slot, displacement))
            else:
                rip_relative = _parse_riprel_operand(memory_text, insn_addr, insn_size)
                if rip_relative is not None:
                    target, width = rip_relative
                    if width is not None:
                        result = _memory_immediate_item("storeirip", immediate_text, width, target)
                else:
                    width = _explicit_memory_width(memory_text)
                    indexed = _parse_indexed_operand(memory_text, base_optional=True)
                    if width is not None and indexed is not None:
                        base_slot, index_slot, shift, displacement = indexed
                        if base_slot < 0:
                            operands: Any = (index_slot, shift, displacement)
                            kind = "storeiidxnb"
                        else:
                            operands = (base_slot, index_slot, shift, displacement)
                            kind = "storeiidx"
                        result = _memory_immediate_item(kind, immediate_text, width, operands)
    return result


def _explicit_memory_width(text: str) -> int | None:
    head = text.strip().lower().split(None, 1)
    return _INDEXED_MEMORY_WIDTHS.get(head[0]) if head else None


def _memory_immediate_item(kind: str, text: str, width: int, operands: Any) -> tuple[Any, ...] | None:
    try:
        value = int(text, 0)
    except ValueError:
        return None
    if width == _QWORD_WIDTH_BITS and value >= 1 << 63:
        value -= 1 << 64
    accepted_width = 32 if width == _QWORD_WIDTH_BITS else width
    if not immediate_fits_width(value, accepted_width):
        return None
    if kind == "storei":
        base_slot, displacement = operands
        return kind, value, base_slot, displacement, width
    if kind == "storeirip":
        return kind, value, operands, width
    if kind == "storeiidxnb":
        index_slot, shift, displacement = operands
        return kind, value, index_slot, shift, displacement, width
    base_slot, index_slot, shift, displacement = operands
    return kind, value, base_slot, index_slot, shift, displacement, width


def _decode_atomic_memory_exchange(text: str, mnemonic: str, item_kind: str, locked: bool) -> tuple[Any, ...] | None:
    """Decode a GP-register atomic exchange with a memory operand."""
    result: tuple[Any, ...] | None = None
    parts = text.split(None, 2 if locked else 1)
    operand_text = (
        parts[2]
        if locked and len(parts) == _LOCKED_INSTRUCTION_PART_COUNT
        else parts[1] if not locked and len(parts) == _INSTRUCTION_PART_COUNT else ""
    )
    mnemonic_index = 1 if locked else 0
    prefix_valid = (
        len(parts) > mnemonic_index
        and parts[mnemonic_index].lower() == mnemonic
        and (not locked or parts[0].lower() == "lock")
    )
    if prefix_valid and "," in operand_text:
        left, right = (token.strip() for token in operand_text.split(",", 1))
        left_mem, right_mem = "[" in left, "[" in right
        if left_mem != right_mem:
            mem_text, register_text = (left, right) if left_mem else (right, left)
            register = _register_operand(register_text.lower())
            if register is not None and register[1] in (32, 64):
                register_slot, register_width = register
                memory = _parse_mem_operand(mem_text)
                if memory is not None:
                    base_slot, displacement, memory_width = memory
                    if memory_width is None or memory_width == register_width:
                        result = (item_kind, register_slot, base_slot, displacement, register_width)
                else:
                    indexed = _parse_indexed_operand(mem_text)
                    if indexed is not None:
                        width_name = mem_text.strip().lower().split(None, 1)[0]
                        memory_width = _INDEXED_MEMORY_WIDTHS.get(width_name)
                        if memory_width is None or memory_width == register_width:
                            base_slot, index_slot, shift, displacement = indexed
                            result = (
                                f"{item_kind}idx",
                                register_slot,
                                base_slot,
                                index_slot,
                                shift,
                                displacement,
                                register_width,
                            )
    return result


def _decode_xchg_memory(text: str) -> tuple[Any, ...] | None:
    """Decode an atomic ``xchg`` between a 32/64-bit GP register and memory.

    An x86 exchange with a memory operand is implicitly locked, so the handler
    must use the native instruction rather than emulate it as separate loads and
    stores. Byte and word forms remain native because the VM only exposes full
    register slots for this atomic operation.
    """
    return _decode_atomic_memory_exchange(text, "xchg", "xchgmem", False)


def _decode_cmpxchg_memory(text: str) -> tuple[Any, ...] | None:
    """Decode a locked ``cmpxchg`` between a 32/64-bit GP register and memory."""
    return _decode_atomic_memory_exchange(text, "cmpxchg", "cmpxchgmem", True)


_LOCKED_RMW_MNEMONICS = frozenset({"add", "sub", "and", "or", "xor", "xadd"})


def _locked_memory_rmw_header(text: str) -> tuple[str, str, str] | None:
    """Return mnemonic and operands for a locked register-source RMW."""
    parts = text.split(None, 2)
    if len(parts) != _LOCKED_INSTRUCTION_PART_COUNT or parts[0].lower() != "lock":
        return None
    mnemonic = parts[1].lower()
    if mnemonic not in _LOCKED_RMW_MNEMONICS or "," not in parts[2]:
        return None
    memory_text, register_text = (token.strip() for token in parts[2].split(",", 1))
    if "[" not in memory_text or "[" in register_text:
        return None
    return mnemonic, memory_text, register_text


def _decode_locked_memory_rmw_indexed(mnemonic: str, memory_text: str, register_text: str) -> tuple[Any, ...] | None:
    """Decode an indexed locked register-source RMW."""
    indexed = _parse_indexed_operand(memory_text, base_optional=True)
    if indexed is None:
        return None
    register = _memory_register_operand(register_text.lower())
    if register is None or register[1] not in (_DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
        return None
    register_slot, register_width = register
    width_name = memory_text.lower().split(None, 1)[0]
    memory_width = _INDEXED_MEMORY_WIDTHS.get(width_name)
    if memory_width is not None and memory_width != register_width:
        return None
    base_slot, index_slot, shift, displacement = indexed
    kind = "atomicmemidxnb" if base_slot < 0 else "atomicmemidx"
    if base_slot < 0:
        return kind, mnemonic, register_slot, index_slot, shift, displacement, register_width
    return kind, mnemonic, register_slot, base_slot, index_slot, shift, displacement, register_width


def _decode_locked_memory_rmw(text: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode a locked GP-register read-modify-write with memory as destination."""
    header = _locked_memory_rmw_header(text)
    if header is None:
        return None
    mnemonic, memory_text, register_text = header
    direct_or_rip = _decode_reg_memory(
        f"{mnemonic} {memory_text}, {register_text}",
        insn_addr,
        insn_size,
        _MemorySourceSpec(
            mnemonic,
            ("atomicmem", mnemonic),
            ("atomicmemrip", mnemonic),
            memory_destination=True,
        ),
    )
    if direct_or_rip is not None:
        return direct_or_rip
    return _decode_locked_memory_rmw_indexed(mnemonic, memory_text, register_text)


def _decode_memory_mov_indexed(text: str) -> tuple[Any, ...] | None:
    """Decode indexed GP loads/stores with or without a base register.

    Returns ``("loadidx"|"storeidx", reg_slot, base_slot, index_slot, shift, disp,
    width)`` or the shorter ``idxnb`` form when the address has no base register.
    Non-indexed, rip-relative, segment, memory-to-memory, and non-GP operands stay
    native.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "mov" or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    left_mem, right_mem = "[" in left, "[" in right
    if left_mem == right_mem:
        return None  # register-to-register or memory-to-memory are not loads/stores
    if left_mem:
        kind, mem_text, reg_text = "storeidx", left, right
    else:
        kind, mem_text, reg_text = "loadidx", right, left
    parsed = _parse_indexed_operand(mem_text, base_optional=True)
    reg = _memory_register_operand(reg_text.lower())
    if parsed is None or reg is None:
        return None
    base_slot, index_slot, shift, disp = parsed
    if base_slot < 0:
        return (f"{kind}nb", reg[0], index_slot, shift, disp, reg[1])
    return (kind, reg[0], base_slot, index_slot, shift, disp, reg[1])


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
        width = {"qword": 64, "dword": 32, "word": _WORD_WIDTH_BITS, "byte": _BYTE_WIDTH_BITS}.get(head[0])
        text = head[1].strip() if len(head) > 1 and width is not None else ""
    rest = text.split(None, 1)
    if rest and rest[0] == "ptr":
        text = rest[1].strip() if len(rest) > 1 else ""
    if not (text.startswith("[") and text.endswith("]")):
        return None
    inner = text[1:-1].strip()
    try:
        absolute = int(inner, 0)
    except ValueError:
        pass
    else:
        if 0 <= absolute < 1 << 64:
            return absolute, width
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
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "mov" or "," not in parts[1]:
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
    reg = _memory_register_operand(reg_text.lower())
    if parsed is None or reg is None:
        return None
    target, mem_width = parsed
    reg_slot, reg_width = reg
    if mem_width is not None and mem_width != reg_width:
        return None
    return (kind, reg_slot, target, reg_width)


@dataclass(frozen=True)
class _MemorySourceSpec:
    mnemonic: str
    direct_prefix: tuple[Any, ...]
    rip_prefix: tuple[Any, ...]
    memory_destination: bool = False


def _decode_reg_memory(
    text: str,
    insn_addr: int,
    insn_size: int,
    spec: _MemorySourceSpec,
) -> tuple[Any, ...] | None:
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != spec.mnemonic or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    memory_text, register_text = (left, right) if spec.memory_destination else (right, left)
    if "[" not in memory_text or "[" in register_text:
        return None
    register = _memory_register_operand(register_text.lower())
    if register is None:
        return None

    register_slot, register_width = register
    result: tuple[Any, ...] | None = None
    memory = _parse_mem_operand(memory_text)
    rip_relative = _parse_riprel_operand(memory_text, insn_addr, insn_size)
    if memory is not None:
        base_slot, displacement, memory_width = memory
        if memory_width is None or memory_width == register_width:
            result = (*spec.direct_prefix, register_slot, base_slot, displacement, register_width)
    elif rip_relative is not None:
        target, memory_width = rip_relative
        if memory_width is None or memory_width == register_width:
            result = (*spec.rip_prefix, register_slot, target, register_width)
    return result


def _decode_cmp_mem(text: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode ``cmp reg, [base+disp]`` / ``cmp reg, [rip+disp]``.

    Returns ``("cmpmem", reg_slot, base_slot, disp, width)`` or
    ``("cmpriprel", reg_slot, target, width)``, or ``None``. Only a register
    left operand against a memory right operand is accepted.
    """
    return _decode_reg_memory(
        text,
        insn_addr,
        insn_size,
        _MemorySourceSpec("cmp", ("cmpmem",), ("cmpriprel",)),
    )


def _decode_op_mem(text: str, mnemonic: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode ``<op> reg, [base+disp]`` / ``<op> reg, [rip+disp]`` for an
    arithmetic mnemonic, where the register is both source and destination.

    Returns ``("opmem", mnemonic, reg_slot, base_slot, disp, width)`` or
    ``("opriprel", mnemonic, reg_slot, target, width)``, or ``None``.
    """
    return _decode_reg_memory(
        text,
        insn_addr,
        insn_size,
        _MemorySourceSpec(mnemonic, ("opmem", mnemonic), ("opriprel", mnemonic)),
    )


def _decode_movx_memory(
    extension: str,
    source_size: int,
    destination: tuple[int, int],
    operand: str,
) -> tuple[Any, ...] | None:
    memory = _parse_mem_operand(operand)
    if memory is not None:
        base_slot, displacement, _memory_width = memory
        return ("movx", extension, source_size, destination[1], destination[0], base_slot, displacement)
    indexed = _parse_indexed_operand(operand)
    if indexed is None:
        return None
    base_slot, index_slot, shift, displacement = indexed
    return (
        "movxidx",
        extension,
        source_size,
        destination[1],
        destination[0],
        base_slot,
        index_slot,
        shift,
        displacement,
    )


def _decode_movx_register(extension: str, destination: tuple[int, int], source_name: str) -> tuple[Any, ...] | None:
    for source_size, registers in (
        (8, REGISTER8_INDEX),
        (16, REGISTER16_INDEX),
        (32, REGISTER32_INDEX),
    ):
        if source_name in registers:
            return ("movxreg", extension, source_size, destination[1], destination[0], registers[source_name])
    return None


def _decode_movx(text: str) -> tuple[Any, ...] | None:
    """Decode ``movzx/movsx/movsxd reg, <source>`` (zero-/sign-extending move).

    r2 reports these under the mov type. The destination is a 32- or 64-bit
    register. A ``byte|word|dword [mem]`` source returns ``("movx", ...)`` (base+disp)
    or ``("movxidx", ...)`` (scaled index); an 8-, 16-, or 32-bit *register* source
    returns ``("movxreg", ext, src_size, dst_width, dst_slot, src_slot)``. ``ext`` is
    ``"z"`` or ``"s"``; ``movsxd`` is the sign-extending dword->qword form (``ext``
    ``"s"``, src_size 32). None when unsupported.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or "," not in parts[1]:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("movzx", "movsx", "movsxd"):
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    dst = _register_operand(left.lower())
    if dst is None:
        return None
    ext = "z" if mnemonic == "movzx" else "s"
    size_word, _, remainder = right.lower().partition(" ")
    if size_word in _MOVX_SRC_SIZES:
        src_size = _MOVX_SRC_SIZES[size_word]
        return _decode_movx_memory(ext, src_size, dst, remainder.strip())
    # Register source: the source register's full value already lives in its slot,
    # so its low byte/word is the operand - no memory access and no flags.
    return _decode_movx_register(ext, dst, right.lower().strip())


def _decode_not_memory(operand: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    result: tuple[Any, ...] | None = None
    memory = _parse_mem_operand(operand)
    if memory is not None:
        base_slot, displacement, width = memory
        if width in (_BYTE_WIDTH_BITS, _WORD_WIDTH_BITS, _DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
            result = ("notmem", base_slot, displacement, width)
    rip_relative = _parse_riprel_operand(operand, insn_addr, insn_size)
    if result is None and rip_relative is not None:
        target, width = rip_relative
        if width in (_BYTE_WIDTH_BITS, _WORD_WIDTH_BITS, _DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
            result = ("notmemrip", target, width)
    indexed = _parse_indexed_operand(operand, base_optional=True)
    if result is None and indexed is not None:
        base_slot, index_slot, shift, displacement = indexed
        width = _explicit_memory_width(operand)
        if width in (_BYTE_WIDTH_BITS, _WORD_WIDTH_BITS, _DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
            result = (
                ("notmemidxnb", index_slot, shift, displacement, width)
                if base_slot < 0
                else ("notmemidx", base_slot, index_slot, shift, displacement, width)
            )
    return result


def _decode_not(text: str, insn_addr: int = 0, insn_size: int = 0) -> tuple[Any, ...] | None:
    """Decode register and direct/indexed/RIP-relative memory ``not`` forms.

    ``not`` sets no flags and touches only its operand, so the handler runs the real
    complement on the slot with no flag capture. A sub-32-bit form complements only
    the low byte/word of the loaded slot, preserving the upper bytes; a 32-bit form
    zero-extends, both exactly as the native instruction. Memory forms carry a
    dummy register field in the bytecode so they can reuse
    the existing address layouts.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "not":
        return None
    operand = parts[1].strip().lower()
    memory = _decode_not_memory(operand, insn_addr, insn_size)
    if memory is not None:
        return memory
    if "[" in operand:
        return None
    reg = _register_operand(operand)
    result = ("not", reg[0], reg[1]) if reg is not None else None
    if result is None and operand in REGISTER8_INDEX:
        result = ("not", REGISTER8_INDEX[operand], 8)
    if result is None and operand in REGISTER16_INDEX:
        result = ("not", REGISTER16_INDEX[operand], 16)
    return result


def _decode_bit_index(text: str, width: int) -> tuple[int, bool] | None:
    result: tuple[int, bool] | None = None
    register = _register_operand(text)
    if register is not None and register[1] == width:
        result = (register[0], False)
    elif not any(marker in text for marker in ("[", "]", "rip", ":", "ptr")):
        try:
            immediate = int(text, 0)
        except ValueError:
            immediate = -1
        if 0 <= immediate <= _BYTE_IMMEDIATE_MAX:
            result = (immediate, True)
    return result


def _decode_bt_memory(left: str, right: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    result: tuple[Any, ...] | None = None
    memory = _parse_mem_operand(left)
    if memory is not None:
        base_slot, displacement, width = memory
        if width in (_DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
            bit = _decode_bit_index(right, width)
            if bit is not None:
                result = ("btmem", base_slot, displacement, bit[0], bit[1], width)
    rip_relative = _parse_riprel_operand(left, insn_addr, insn_size)
    if result is None and rip_relative is not None:
        target, width = rip_relative
        if width in (_DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
            bit = _decode_bit_index(right, width)
            if bit is not None:
                result = ("btmemrip", target, bit[0], bit[1], width)
    indexed = _parse_indexed_operand(left, base_optional=True)
    if result is None and indexed is not None:
        base_slot, index_slot, shift, displacement = indexed
        width = _explicit_memory_width(left)
        if width in (_DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
            bit = _decode_bit_index(right, width)
            if bit is not None:
                kind = "btmemidxnb" if base_slot < 0 else "btmemidx"
                result = (
                    (kind, index_slot, shift, displacement, bit[0], bit[1], width)
                    if base_slot < 0
                    else (kind, base_slot, index_slot, shift, displacement, bit[0], bit[1], width)
                )
    return result


def _decode_bt(text: str, insn_addr: int = 0, insn_size: int = 0) -> tuple[Any, ...] | None:
    """Decode register and direct/indexed/RIP-relative memory bit tests.

    ``bt`` copies the selected bit into CF and leaves ZF unchanged (the other status
    flags are architecturally undefined); the handler runs the real ``bt`` and merges
    its CF into the flags slot, keeping the rest. The value register and either a
    register bit index or an immediate one are supported. Returns
    ``("bt", value_slot, index_value, is_immediate, width)``.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "bt" or "," not in parts[1]:
        return None
    left, right = (token.strip().lower() for token in parts[1].split(",", 1))
    memory = _decode_bt_memory(left, right, insn_addr, insn_size)
    if memory is not None:
        return memory
    if "[" in left or "[" in right:
        return None
    value = _register_operand(left)
    if value is None or value[1] not in (32, 64):
        return None
    slot, width = value
    result: tuple[Any, ...] | None = None
    index = _register_operand(right)
    if index is not None:
        if index[1] == width:
            result = ("bt", slot, index[0], False, width)
    elif not any(marker in right for marker in ("[", "]", "rip", ":", "ptr")):
        try:
            immediate = int(right, 0)
        except ValueError:
            immediate = -1
        if 0 <= immediate < width:
            result = ("bt", slot, immediate, True, width)
    return result


def _decode_div_memory(mnemonic: str, operand: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    signedness = "s" if mnemonic == "idiv" else "u"
    result: tuple[Any, ...] | None = None
    memory = _parse_mem_operand(operand)
    if memory is not None:
        base_slot, displacement, width = memory
        if width in (_DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
            result = ("divmem", signedness, base_slot, displacement, width)
    rip_relative = _parse_riprel_operand(operand, insn_addr, insn_size)
    if result is None and rip_relative is not None:
        target, width = rip_relative
        if width in (_DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
            result = ("divmemrip", signedness, target, width)
    indexed = _parse_indexed_operand(operand, base_optional=True)
    if result is None and indexed is not None:
        base_slot, index_slot, shift, displacement = indexed
        width = _explicit_memory_width(operand)
        if width in (_DWORD_WIDTH_BITS, _QWORD_WIDTH_BITS):
            kind = "divmemidxnb" if base_slot < 0 else "divmemidx"
            result = (
                (kind, signedness, index_slot, shift, displacement, width)
                if base_slot < 0
                else (kind, signedness, base_slot, index_slot, shift, displacement, width)
            )
    return result


def _decode_div(text: str, insn_addr: int = 0, insn_size: int = 0) -> tuple[Any, ...] | None:
    """Decode register and direct/indexed/RIP-relative memory ``div`` forms.

    The dividend is the implicit ``rdx:rax`` pair and the results are the quotient in
    rax and the remainder in rdx; the handler runs the real ``div``/``idiv`` so the
    quotient, remainder and the #DE on divide-by-zero all match the native op (its
    flags are architecturally undefined, so none are captured). A memory divisor is
    left native. Returns ``("div", "s"|"u", divisor_slot, width)``.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("div", "idiv"):
        return None
    operand = parts[1].strip().lower()
    memory = _decode_div_memory(mnemonic, operand, insn_addr, insn_size)
    if memory is not None:
        return memory
    if "[" in operand:
        return None
    reg = _register_operand(operand)
    if reg is None or reg[1] not in (32, 64):
        return None
    return ("div", "s" if mnemonic == "idiv" else "u", reg[0], reg[1])


def _decode_cqo(text: str) -> tuple[Any, ...] | None:
    """Decode ``cqo`` / ``cdq`` (sign-extend rax into rdx, setting up an idiv).

    Sets no flags and takes no explicit operand: rax is sign-extended into rdx (the
    64-bit ``cqo`` or the 32-bit ``cdq``). Returns ``("cqo", width)``.
    """
    mnemonic = text.split(maxsplit=1)[0].lower() if text else ""
    if mnemonic == "cqo":
        return ("cqo", 64)
    if mnemonic == "cdq":
        return ("cqo", 32)
    return None


def _decode_bswap(text: str) -> tuple[Any, ...] | None:
    """Decode ``bswap reg`` (byte-order reversal, register operand, 32/64-bit only).

    ``bswap`` sets no flags and is defined only for 32- and 64-bit operands, so the
    handler runs the real byte swap on the slot with no flag capture. Returns
    ``("bswap", reg_slot, width)`` or ``None``.
    """
    parts = text.split()
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "bswap":
        return None
    reg = _register_operand(parts[1].lower())
    if reg is None or reg[1] not in (32, 64):
        return None
    return ("bswap", reg[0], reg[1])


def _decode_incdec(text: str) -> tuple[Any, ...] | None:
    """Decode ``inc reg`` / ``dec reg`` (register operand).

    r2 reports inc/dec under the add/sub types, so this is tried in the
    arithmetic path. inc/dec preserve CF (unlike add/sub by one), so the handler
    runs the real instruction. Returns ``("incdec", mnemonic, reg_slot, width)``.
    """
    parts = text.split()
    if len(parts) != _INSTRUCTION_PART_COUNT:
        return None
    mnemonic = parts[0].lower()
    if mnemonic not in ("inc", "dec") or "[" in parts[1]:
        return None
    operand = parts[1].lower()
    reg = _register_operand(operand)
    if reg is not None:
        return ("incdec", mnemonic, reg[0], reg[1])
    # Sub-32-bit register (inc al / dec dx - a byte or word counter). The handler
    # merges the low byte(s) back into the slot, preserving the upper bytes.
    if operand in REGISTER8_INDEX:
        return ("incdec", mnemonic, REGISTER8_INDEX[operand], 8)
    if operand in REGISTER16_INDEX:
        return ("incdec", mnemonic, REGISTER16_INDEX[operand], 16)
    return None


def _decode_op_memdst(text: str, mnemonic: str, insn_addr: int, insn_size: int) -> tuple[Any, ...] | None:
    """Decode ``<op> [base+disp], reg`` / ``<op> [rip+disp], reg`` (memory is the
    read-modify-write destination, the register is the source).

    Returns ``("opmemdst", mnemonic, reg_slot, base_slot, disp, width)`` or
    ``("opmemdstrip", mnemonic, reg_slot, target, width)``, or ``None``.
    """
    return _decode_reg_memory(
        text,
        insn_addr,
        insn_size,
        _MemorySourceSpec(
            mnemonic,
            ("opmemdst", mnemonic),
            ("opmemdstrip", mnemonic),
            memory_destination=True,
        ),
    )


_SCALE_TO_SHIFT = {1: 0, 2: 1, 4: 2, 8: 3}


@dataclass
class _IndexedOperand:
    base: int | None = None
    index: int | None = None
    shift: int | None = None
    displacement: int = 0


def _consume_indexed_token(token: str, operand: _IndexedOperand) -> bool:
    valid = True
    if "*" in token:
        index_name, scale_text = token.split("*", 1)
        try:
            scale = int(scale_text, 0)
        except ValueError:
            scale = 0
            valid = False
        if index_name in REGISTER_INDEX and scale in _SCALE_TO_SHIFT:
            operand.index, operand.shift = REGISTER_INDEX[index_name], _SCALE_TO_SHIFT[scale]
        else:
            valid = False
    elif token in REGISTER_INDEX:
        if operand.base is None:
            operand.base = REGISTER_INDEX[token]
        elif operand.index is None:
            operand.index, operand.shift = REGISTER_INDEX[token], 0
        else:
            valid = False
    else:
        try:
            operand.displacement += int(token, 0)
        except ValueError:
            valid = False
    return valid


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
        if head[0] not in ("qword", "dword", "word", "byte"):
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
    operand = _IndexedOperand()
    for raw_token in (part.strip() for part in inner.replace("-", "+-").split("+")):
        if not raw_token:
            continue
        token = raw_token.replace(" ", "")
        if not _consume_indexed_token(token, operand):
            return None
    result: tuple[int, int, int, int] | None = None
    if operand.index is not None and operand.shift is not None:
        if operand.base is not None:
            result = (operand.base, operand.index, operand.shift, operand.displacement)
        elif base_optional:
            result = (-1, operand.index, operand.shift, operand.displacement)
    return result


def _decode_op_mem_indexed(text: str, mnemonic: str) -> tuple[Any, ...] | None:
    """Decode ``<op> reg, [base + index*scale + disp]`` (scaled-index memory
    source, register source/destination).

    Returns ``("opmemidx", mnemonic, reg_slot, base_slot, index_slot, shift,
    disp, width)`` or ``None``.
    """
    parts = text.split(None, 1)
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != mnemonic or "," not in parts[1]:
        return None
    left, right = (token.strip() for token in parts[1].split(",", 1))
    if "[" in left or "[" not in right:
        return None
    reg = _memory_register_operand(left.lower())
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
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "lea" or "," not in parts[1]:
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
    if len(parts) != _INSTRUCTION_PART_COUNT or parts[0].lower() != "lea" or "," not in parts[1]:
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
