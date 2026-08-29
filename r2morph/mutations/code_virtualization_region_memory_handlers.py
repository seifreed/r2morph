"""Memory and address handler assembly for region virtualization."""

from __future__ import annotations

from dataclasses import dataclass

from r2morph.mutations.code_virtualization_fold import addr_fold, arith_fold
from r2morph.mutations.code_virtualization_layout import idx_offsets, mem_offsets
from r2morph.mutations.code_virtualization_region_compare import compare_compute
from r2morph.mutations.code_virtualization_region_flags import synth_flags_asm as _synth_flags_asm
from r2morph.mutations.code_virtualization_region_handlers import (
    _BYTE_WIDTH_BITS,
    _DWORD_WIDTH_BITS,
    _FLAGS_OFFSET,
    _QWORD_WIDTH_BITS,
    _WORD_WIDTH_BITS,
    _unmask_dword,
)


@dataclass(frozen=True)
class MemoryOperationConfig:
    handler_key: str
    key: str
    key_dword: str
    field_perm: int = 0
    flag_variant: int = 0
    arith_variant: int = 0
    compare_variant: int = 0
    addr_variant: int = 0


@dataclass(frozen=True)
class AtomicMemoryOperationConfig:
    handler_key: str
    key: str
    key_dword: str
    slot: tuple[int, ...]
    field_perm: int = 0
    addr_variant: int = 0


def _memory_load_slot_asm(width: int) -> str:
    if width == _QWORD_WIDTH_BITS:
        return "  mov rax, qword ptr [r10]\n  mov qword ptr [rsp+r8*8], rax\n"
    if width == _DWORD_WIDTH_BITS:
        return "  mov eax, dword ptr [r10]\n  mov qword ptr [rsp+r8*8], rax\n"
    load = "byte" if width == _BYTE_WIDTH_BITS else "word"
    mask = -256 if width == _BYTE_WIDTH_BITS else -65536
    return (
        f"  movzx eax, {load} ptr [r10]\n"
        f"  mov r11, qword ptr [rsp+r8*8]\n  and r11, {mask}\n  or rax, r11\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
    )


def _memory_store_slot_asm(width: int) -> str:
    value = {
        _BYTE_WIDTH_BITS: ("byte", "al"),
        _WORD_WIDTH_BITS: ("word", "ax"),
        _DWORD_WIDTH_BITS: ("dword", "eax"),
        _QWORD_WIDTH_BITS: ("qword", "rax"),
    }[width]
    return f"  mov rax, qword ptr [rsp+r8*8]\n  mov {value[0]} ptr [r10], {value[1]}\n"


def _mem_address_asm(
    riprel: bool, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> tuple[str, int]:
    """Shared head of every memory handler: decrypt the register slot into r8
    and compute the effective address into r10.

    For the rip-relative form the address is the bytecode base (r15) plus the
    stored signed offset; otherwise it is a frame-slot base value plus a signed
    displacement. The operand fields are read at this build's permuted offsets
    (the encoder emits them in the same order), so the layout differs per build.
    Returns the assembly and the number of bytes to advance rsi by.
    """
    off = mem_offsets(riprel, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if riprel:
        return (
            body
            + f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
            + _unmask_dword("r11")
            + "  movsxd rax, eax\n  mov r10, r15\n"
            + addr_fold("rax", "rcx", 0, addr_variant)
        ), 6
    return (
        body + f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
        + _unmask_dword("r11")
        + "  movsxd rax, eax\n  mov r10, qword ptr [rsp+r9*8]\n"
        + addr_fold("rax", "rcx", 0, addr_variant)
    ), 7


def _memory_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> str:
    """Assembly body for a load/store handler (``mov`` reg <-> [base+disp]).

    The base value is read from its frame slot (so rsp resolves to the captured
    original rsp, and any base updated earlier in the run is seen at its current
    value), the signed displacement is added, and the qword/dword is moved. A
    32-bit load zero-extends, matching x86-64. ``mov`` sets no flags, so the
    captured-flags slot is untouched.
    """
    kind, width_text = handler_key.split("_")
    width = int(width_text)
    body, advance = _mem_address_asm(False, key, key_dword, field_perm, addr_variant)
    if kind == "load":
        body += _memory_load_slot_asm(width)
    else:
        body += _memory_store_slot_asm(width)
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _xchg_memory_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Atomically exchange a GP slot with a 32/64-bit memory value."""
    _, width_text = handler_key.split("_")
    width = int(width_text)
    body, advance = _mem_address_asm(False, key, key_dword, field_perm, addr_variant)
    memory = "qword" if width == _QWORD_WIDTH_BITS else "dword"
    register = "rax" if width == _QWORD_WIDTH_BITS else "eax"
    body += (
        f"  mov {register}, {memory} ptr [rsp+r8*8]\n"
        f"  xchg {memory} ptr [r10], {register}\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
    )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _xchg_memory_indexed_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Atomically exchange a GP slot with a scaled-index memory value."""
    _, width_text = handler_key.split("_")
    width = int(width_text)
    body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    memory = "qword" if width == _QWORD_WIDTH_BITS else "dword"
    register = "rax" if width == _QWORD_WIDTH_BITS else "eax"
    body += (
        f"  mov {register}, {memory} ptr [rsp+r8*8]\n"
        f"  xchg {memory} ptr [r10], {register}\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
    )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _cmpxchg_memory_handler_asm(config: AtomicMemoryOperationConfig, indexed: bool = False) -> str:
    """Atomically compare the accumulator with memory and conditionally store a GP value."""
    _, width_text = config.handler_key.split("_")
    width = int(width_text)
    address = _indexed_address_asm if indexed else _mem_address_asm
    address_arguments = (
        (config.key, config.key_dword, config.field_perm, config.addr_variant)
        if indexed
        else (False, config.key, config.key_dword, config.field_perm, config.addr_variant)
    )
    body, advance = address(*address_arguments)
    memory = "qword" if width == _QWORD_WIDTH_BITS else "dword"
    register = "rbx" if width == _QWORD_WIDTH_BITS else "ebx"
    accumulator = "rax" if width == _QWORD_WIDTH_BITS else "eax"
    body += (
        f"  mov {register}, qword ptr [rsp+r8*8]\n"
        f"  mov {accumulator}, qword ptr [rsp+{config.slot[0] * 8}]\n"
        f"  lock cmpxchg {memory} ptr [r10], {register}\n"
        f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        f"  mov qword ptr [rsp+{config.slot[0] * 8}], rax\n"
    )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _tls_address_asm(
    has_base: bool,
    key: str,
    key_dword: str,
    field_perm: int = 0,
) -> tuple[str, int]:
    """Decode a TLS displacement and form its address without changing the segment base."""
    off = mem_offsets(not has_base, field_perm)
    body = f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
    if has_base:
        body += f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
    body += (
        f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
        + _unmask_dword("r11")
        + "  movsxd rax, eax\n"
    )
    if has_base:
        body += "  mov r10, qword ptr [rsp+r9*8]\n  lea r10, [r10+rax]\n"
    else:
        body += "  mov r10, rax\n"
    return body, 7 if has_base else 6


def _tls_memory_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Load or store a GP value through the current thread's FS/GS base."""
    parts = handler_key.split("_")
    kind, segment, width_text = parts[0], parts[1], parts[-1]
    width = int(width_text)
    if kind.endswith("idxnb"):
        body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    elif kind.endswith("idx"):
        body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    else:
        base = parts[2]
        body, advance = _tls_address_asm(base not in ("-1", "None"), key, key_dword, field_perm)
    address = f"{segment}:[r10]"
    if kind.startswith("tlsload"):
        load = (
            f"  mov rax, qword ptr {address}\n" if width == _QWORD_WIDTH_BITS else f"  mov eax, dword ptr {address}\n"
        )
        body += load + "  mov qword ptr [rsp+r8*8], rax\n"
    else:
        body += "  mov rbx, qword ptr [rsp+r8*8]\n"
        value = "rbx" if width == _QWORD_WIDTH_BITS else "ebx"
        size = "qword" if width == _QWORD_WIDTH_BITS else "dword"
        body += f"  mov {size} ptr {address}, {value}\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _riprel_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> str:
    """Assembly body for a rip-relative load/store handler.

    The target is recomputed as bytecode-base (r15) plus the stored signed
    offset, so it reaches the same global the original ``[rip+disp]`` did and
    stays correct under rebasing (the global and the VM share one image).
    """
    _, sub, width_text = handler_key.split("_")
    width = int(width_text)
    body, advance = _mem_address_asm(True, key, key_dword, field_perm, addr_variant)
    if sub == "load":
        body += _memory_load_slot_asm(width)
    else:
        body += _memory_store_slot_asm(width)
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _cmp_memory_handler_asm(config: MemoryOperationConfig) -> str:
    """Assembly body for ``cmp reg, [mem]`` (computes the address, synthesizes flags).

    The memory address comes from a frame-slot base plus displacement (``cmpmem``)
    or the bytecode base plus a stored offset (``cmpriprel``). The comparison is the
    register minus the loaded memory value, computed with the MBA fold and its flags
    synthesized by hand (no literal cmp, no pushfq), exactly like the register/
    immediate compare handler; nothing is written back.
    """
    parts = config.handler_key.split("_")
    riprel = parts[0] == "cmpriprel"
    width = int(parts[-1])
    body, advance = _mem_address_asm(
        riprel,
        config.key,
        config.key_dword,
        config.field_perm,
        config.addr_variant,
    )
    # a = the register operand, b = the memory operand; compute a - b via MBA.
    if width == _QWORD_WIDTH_BITS:
        body += "  mov rbx, qword ptr [rsp+r8*8]\n  mov rax, qword ptr [r10]\n"
    else:
        body += "  mov ebx, dword ptr [rsp+r8*8]\n  mov eax, dword ptr [r10]\n"
    body += "  mov rbp, rax\n"
    if config.compare_variant == 0:
        body += "  neg rax\n  mov r10, rbx\n" + arith_fold("add", 0, config.arith_variant)
    else:
        body += compare_compute("cmp", 0, config.arith_variant, config.compare_variant)
    if width == _DWORD_WIDTH_BITS:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(width, "sub", config.flag_variant)
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_memdst_handler_asm(config: MemoryOperationConfig) -> str:
    """Assembly body for ``<op> [mem], reg`` (memory is the read-modify-write
    destination, the register is the source).

    The address is computed with the shared prologue and kept in r12 (free scratch)
    so the result can be written back to memory after the MBA fold; the memory value
    is a, the register is b, and the flags are synthesized (no literal op, no pushfq).
    """
    parts = config.handler_key.split("_")
    riprel = parts[0] == "opmemdstrip"
    mnemonic, width = parts[1], int(parts[2])
    body, advance = _mem_address_asm(
        riprel,
        config.key,
        config.key_dword,
        config.field_perm,
        config.addr_variant,
    )
    body += "  mov r12, r10\n"
    if width == _QWORD_WIDTH_BITS:
        body += "  mov rbx, qword ptr [r12]\n  mov rax, qword ptr [rsp+r8*8]\n"
    else:
        body += "  mov ebx, dword ptr [r12]\n  mov eax, dword ptr [rsp+r8*8]\n"
    body += "  mov rbp, rax\n"
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += "  mov r10, rbx\n"
    body += arith_fold(mnemonic, 0, config.arith_variant)
    if width == _DWORD_WIDTH_BITS:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(
        width,
        mnemonic if mnemonic in ("add", "sub") else "logic",
        config.flag_variant,
    )
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    if width == _QWORD_WIDTH_BITS:
        body += "  mov qword ptr [r12], r10\n"
    else:
        body += "  mov dword ptr [r12], r10d\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _movx_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> str:
    """Assembly body for ``movzx/movsx reg, byte|word [base+disp]``.

    The address is computed with the shared prologue, then the byte or word is
    zero- or sign-extended into the destination slot. movzx always zero-extends
    the same regardless of destination width; movsx's extension target depends
    on whether the destination is 32- or 64-bit. movzx/movsx set no flags.
    """
    _, ext, src_size_text, dst_width_text = handler_key.split("_")
    body, advance = _mem_address_asm(False, key, key_dword, field_perm, addr_variant)
    return body + _movx_extend_asm(ext, int(src_size_text), int(dst_width_text), advance)


def _movx_load_asm(ext: str, src_size: int, dst_width: int) -> str:
    """Load a byte/word/dword from ``[r10]`` into rax with zero- or sign-extension.

    movzx always zero-extends the same regardless of destination width; movsx's
    extension target depends on whether the destination is 32- or 64-bit. A dword
    source is the movsxd form, which always sign-extends into a 64-bit register.
    Shared by the single-handler movx tail and the vmovx micro-op (which pushes rax
    instead of storing it to a slot)."""
    if src_size == _DWORD_WIDTH_BITS:
        return "  movsxd rax, dword ptr [r10]\n"
    size_word = "byte" if src_size == _BYTE_WIDTH_BITS else "word"
    if ext == "z":
        return f"  movzx eax, {size_word} ptr [r10]\n"
    if dst_width == _QWORD_WIDTH_BITS:
        return f"  movsx rax, {size_word} ptr [r10]\n"
    return f"  movsx eax, {size_word} ptr [r10]\n"


def _movx_extend_asm(ext: str, src_size: int, dst_width: int, advance: int) -> str:
    """The extend-from-[r10]-into-the-slot tail shared by the movzx/movsx handlers."""
    load = _movx_load_asm(ext, src_size, dst_width)
    return load + f"  mov qword ptr [rsp+r8*8], rax\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _movx_indexed_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Assembly body for ``movzx/movsx reg, byte|word [base+index*scale+disp]``."""
    _, ext, src_size_text, dst_width_text = handler_key.split("_")
    body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    return body + _movx_extend_asm(ext, int(src_size_text), int(dst_width_text), advance)


def _indexed_address_asm(key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> tuple[str, int]:
    """Shared head of every indexed memory handler: decrypt the register slot
    into r8 and compute ``base + index*scale + disp`` into r10.

    The index is read from its slot and shifted by the encoded scale log2, then
    the base and displacement are added. The operand fields are read at this
    build's permuted offsets (the encoder emits them in the same order). Returns
    the assembly and the rsi advance (the bytecode item width).
    """
    off = idx_offsets(False, field_perm)
    return (
        f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r9d, byte ptr [rsi+{off['base']}]\n  xor r9b, {key}\n  xor r9b, r13b\n"
        f"  movzx r11d, byte ptr [rsi+{off['index']}]\n  xor r11b, {key}\n  xor r11b, r13b\n"
        f"  movzx ecx, byte ptr [rsi+{off['shift']}]\n  xor cl, {key}\n  xor cl, r13b\n"
        f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r10d, {key_dword}\n  xor eax, r10d\n"
        + _unmask_dword("r10")
        + "  movsxd rax, eax\n  mov r10, qword ptr [rsp+r11*8]\n  shl r10, cl\n"
        # Fold the base with MBA too (r11 holds the base value), so neither the
        # base nor the displacement add is a literal add. rcx and r11 are free
        # here (the index slot and scale were already consumed).
        "  mov r11, qword ptr [rsp+r9*8]\n"
        + addr_fold("r11", "rcx", 0, addr_variant)
        + addr_fold("rax", "rcx", 0, addr_variant)
    ), 9


def _indexed_address_nobase_asm(
    key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> tuple[str, int]:
    """Like :func:`_indexed_address_asm` but with no base register: the address is
    ``index*scale + disp``, computed into r10 (r8 holds the decrypted register
    field). The item has no base-slot byte, so the rsi advance is 8."""
    off = idx_offsets(True, field_perm)
    return (
        f"  movzx r8d, byte ptr [rsi+{off['reg']}]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  movzx r11d, byte ptr [rsi+{off['index']}]\n  xor r11b, {key}\n  xor r11b, r13b\n"
        f"  movzx ecx, byte ptr [rsi+{off['shift']}]\n  xor cl, {key}\n  xor cl, r13b\n"
        f"  mov eax, dword ptr [rsi+{off['disp']}]\n  mov r10d, {key_dword}\n  xor eax, r10d\n"
        + _unmask_dword("r10")
        + "  movsxd rax, eax\n  mov r10, qword ptr [rsp+r11*8]\n  shl r10, cl\n"
        + addr_fold("rax", "rcx", 0, addr_variant)
    ), 8


def _lea_store_asm(width: int, advance: int) -> str:
    """The store-address-into-slot tail shared by the lea handlers.

    A 32-bit destination truncates the address to its low 32 bits, zero-extended
    into the 64-bit slot (``mov r10d, r10d`` clears the upper half); a 64-bit
    destination stores the full address.
    """
    truncate = "  mov r10d, r10d\n" if width == _DWORD_WIDTH_BITS else ""
    return f"{truncate}  mov qword ptr [rsp+r8*8], r10\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _lea_indexed_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Assembly body for ``lea reg, [base + index*scale + disp]`` (32- or 64-bit dst).

    The effective address is computed with the shared indexed prologue and
    stored into the destination slot without dereferencing; lea sets no flags.
    """
    width = int(handler_key.split("_")[1])
    body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    return body + _lea_store_asm(width, advance)


def _lea_indexed_nobase_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Assembly body for ``lea reg, [index*scale + disp]`` (no base, 32- or 64-bit dst).

    Like the indexed prologue but without the base add: the address is
    ``index*scale + disp``. The item has no base-slot byte, so it is one byte
    shorter (size 8). Operand fields are read at this build's permuted offsets.
    lea sets no flags; a 32-bit destination truncates.
    """
    width = int(handler_key.split("_")[1])
    body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    return body + _lea_store_asm(width, advance)


def _op_mem_synth_tail(
    mnemonic: str,
    width: int,
    advance: int,
    config: MemoryOperationConfig,
) -> str:
    """Tail shared by ``<op> reg, [mem]`` handlers: with the effective address in
    r10 and the register slot index in r8, compute ``reg <op> [mem]`` with the MBA
    fold, synthesize the flags, store the result to the register slot.

    The register operand is a, the loaded memory operand is b; nothing here spells
    out a literal native op or a pushfq.
    """
    if width == _QWORD_WIDTH_BITS:
        body = "  mov rbx, qword ptr [rsp+r8*8]\n  mov rax, qword ptr [r10]\n"
    else:
        body = "  mov ebx, dword ptr [rsp+r8*8]\n  mov eax, dword ptr [r10]\n"
    body += "  mov rbp, rax\n"
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += "  mov r10, rbx\n"
    body += arith_fold(mnemonic, 0, config.arith_variant)
    if width == _DWORD_WIDTH_BITS:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(
        width,
        mnemonic if mnemonic in ("add", "sub") else "logic",
        config.flag_variant,
    )
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    body += "  mov qword ptr [rsp+r8*8], r10\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_mem_indexed_handler_asm(config: MemoryOperationConfig) -> str:
    """Assembly body for ``<op> reg, [base + index*scale + disp]`` (reg is source
    and destination; memory is the scaled-index source).

    The address is computed with the shared indexed prologue; the result is the
    register combined with memory via the MBA fold and the flags are synthesized.
    """
    _, mnemonic, width_text = config.handler_key.split("_")
    body, advance = _indexed_address_asm(
        config.key,
        config.key_dword,
        config.field_perm,
        config.addr_variant,
    )
    return body + _op_mem_synth_tail(mnemonic, int(width_text), advance, config)


def _lea_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> str:
    """Assembly body for ``lea reg, [base+disp]`` / ``lea reg, [rip+disp]``.

    The effective address is computed exactly like a memory handler, but it is
    stored into the destination slot instead of being dereferenced; lea sets no
    flags. A 32-bit destination truncates the address to its low 32 bits.
    """
    sub, width_text = handler_key.split("_")
    body, advance = _mem_address_asm(sub == "learip", key, key_dword, field_perm, addr_variant)
    return body + _lea_store_asm(int(width_text), advance)


def _op_memory_handler_asm(config: MemoryOperationConfig) -> str:
    """Assembly body for ``<op> reg, [mem]`` (reg is source and destination).

    The address is computed like the compare-with-memory handler; the result is the
    register combined with memory via the MBA fold (a 32-bit op zero-extends) and the
    flags are synthesized.
    """
    parts = config.handler_key.split("_")
    riprel = parts[0] == "opriprel"
    mnemonic, width = parts[1], int(parts[2])
    body, advance = _mem_address_asm(
        riprel,
        config.key,
        config.key_dword,
        config.field_perm,
        config.addr_variant,
    )
    return body + _op_mem_synth_tail(mnemonic, width, advance, config)
