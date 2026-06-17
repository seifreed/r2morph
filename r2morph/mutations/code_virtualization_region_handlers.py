"""
Assembly bodies for the region VM's opcode handlers.

Each function here renders the native assembly for one VM handler instance:
it decrypts the operands embedded in the bytecode stream, applies the real
operation, captures the resulting RFLAGS where the operation defines them,
advances the bytecode pointer, and jumps back to the dispatch loop. The
handlers are pure string builders keyed by a ``handler_key`` and the
per-instance XOR key; :mod:`code_virtualization_region` owns the dispatch
table and stitches these instances together.
"""

from __future__ import annotations

# Stack frame: 16 context slots in [0x00, 0x80), the captured RFLAGS at 0x80,
# and the System V red zone preserved in [0x100, 0x180).
_FRAME_SIZE = 0x180
_FLAGS_OFFSET = 0x80
# The program's virtual stack is relocated this far below the VM frame so the
# function's own push/pop traffic never collides with the spilled context. Must
# be 16-aligned to preserve the program's stack alignment.
_GUARD = 0x200

# Mixed boolean-arithmetic rewrites of ``r10 += rax`` used to fold the signed
# displacement into an effective address, so no literal ``add`` of the
# displacement appears in the handler. Several equivalent identities are kept and
# one is chosen per instance, so the fold is not a single fixed pattern a
# devirtualizer can match across samples. rcx is free scratch in the address
# prologues, and the flags these set are dead (a handler that needs flags runs
# and captures its real operation's flags afterward).
# ``{t}`` is a free temp register, ``{a}`` the addend; each template computes
# ``r10 += {a}`` (a == r10, b == {a}). The closing lea is flag-neutral, but the
# xor/and/or/sub set flags — harmless because these run in a flag-dead prologue.
_MBA_ADD_TEMPLATES: tuple[str, ...] = (
    # a + b == (a ^ b) + 2*(a & b)
    "  mov {t}, r10\n  xor {t}, {a}\n  and r10, {a}\n  lea r10, [{t} + r10*2]\n",
    # a + b == (a | b) + (a & b)
    "  mov {t}, r10\n  and {t}, {a}\n  or r10, {a}\n  lea r10, [r10 + {t}]\n",
    # a + b == 2*(a | b) - (a ^ b)
    "  mov {t}, r10\n  xor {t}, {a}\n  or r10, {a}\n  lea r10, [r10*2]\n  sub r10, {t}\n",
)


def _mba_add(addend: str, temp: str, key: int) -> str:
    """A per-instance MBA rewrite of ``r10 += addend`` (chosen by the bytecode key)."""
    return _MBA_ADD_TEMPLATES[key % len(_MBA_ADD_TEMPLATES)].format(a=addend, t=temp)


def _mba_add_r10_rax(key: int) -> str:
    """The MBA rewrite of ``r10 += rax`` used to fold a displacement."""
    return _mba_add("rax", "rcx", key)


def _op_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str) -> str:
    """Assembly body for an arithmetic/mov handler (decrypts, applies, captures flags)."""
    _, mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
    if is_immediate and width == 64:
        body += f"  mov rax, qword ptr [rsi+2]\n  mov r10, {key_qword}\n  xor rax, r10\n"
        advance = 10
    elif is_immediate:
        body += f"  mov eax, dword ptr [rsi+2]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
        body += "  mov rax, qword ptr [rsp+r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp+r9*8]\n"
        advance = 3
    if mnemonic == "mov":
        body += "  mov qword ptr [rsp+r8*8], rax\n"
    elif width == 64:
        body += f"  {mnemonic} qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
    else:
        body += (
            f"  mov r11d, dword ptr [rsp+r8*8]\n  {mnemonic} r11d, eax\n"
            f"  mov qword ptr [rsp+r8*8], r11\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        )
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_mba_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str) -> str:
    """Assembly body for a flag-dead ``add``/``sub`` handler.

    The region's flag-liveness analysis proved this op's flags are never read, so
    the result is computed with a mixed boolean-arithmetic rewrite (no literal
    add/sub) and no flags are captured. ``sub a, b`` is folded as ``add a, -b``.
    The destination is loaded into r10, the source/immediate into rax, and the
    MBA fold leaves the result in r10. A 32-bit destination zero-extends.
    """
    _, mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    is_immediate = mode == "i"
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
    if is_immediate and width == 64:
        body += f"  mov rax, qword ptr [rsi+2]\n  mov r10, {key_qword}\n  xor rax, r10\n"
        advance = 10
    elif is_immediate:
        body += f"  mov eax, dword ptr [rsi+2]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
        body += "  mov rax, qword ptr [rsp+r9*8]\n" if width == 64 else "  mov eax, dword ptr [rsp+r9*8]\n"
        advance = 3
    # sub a, b == add a, (-b): negate the source, then the same MBA add fold.
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += "  mov r10, qword ptr [rsp+r8*8]\n" if width == 64 else "  mov r10d, dword ptr [rsp+r8*8]\n"
    body += _op_mba_compute(mnemonic, key)
    if width == 64:
        body += "  mov qword ptr [rsp+r8*8], r10\n"
    else:
        body += "  mov r10d, r10d\n  mov qword ptr [rsp+r8*8], r10\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_mba_compute(mnemonic: str, key: int) -> str:
    """Compute ``r10 = r10 <op> rax`` with no literal native op (r10 == a, rax == b).

    add/sub use the polymorphic MBA add fold (sub already negated its source);
    the boolean ops use De Morgan / MBA rewrites, so the handler never contains a
    plain xor/and/or. ``not`` is flag-neutral and the and/or set only dead flags.
    """
    if mnemonic in ("add", "sub"):
        return _mba_add("rax", "rcx", key)
    if mnemonic == "xor":  # a ^ b == (a | b) & ~(a & b)
        return "  mov rcx, r10\n  and rcx, rax\n  or r10, rax\n  not rcx\n  and r10, rcx\n"
    if mnemonic == "and":  # a & b == ~(~a | ~b)
        return "  not r10\n  mov rcx, rax\n  not rcx\n  or r10, rcx\n  not r10\n"
    # a | b == ~(~a & ~b)
    return "  not r10\n  mov rcx, rax\n  not rcx\n  and r10, rcx\n  not r10\n"


def _mem_address_asm(riprel: bool, key: int, key_dword: str) -> tuple[str, int]:
    """Shared head of every memory handler: decrypt the register slot into r8
    and compute the effective address into r10.

    For the rip-relative form the address is the bytecode base (r15) plus the
    stored signed offset; otherwise it is a frame-slot base value plus a signed
    displacement. Returns the assembly and the number of bytes to advance rsi by
    (the bytecode item width).
    """
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
    if riprel:
        return (
            body + f"  mov eax, dword ptr [rsi+2]\n  mov r11d, {key_dword}\n  xor eax, r11d\n  movsxd rax, eax\n"
            "  mov r10, r15\n" + _mba_add_r10_rax(key)
        ), 6
    return (
        body + f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
        f"  mov eax, dword ptr [rsi+3]\n  mov r11d, {key_dword}\n  xor eax, r11d\n  movsxd rax, eax\n"
        "  mov r10, qword ptr [rsp+r9*8]\n" + _mba_add_r10_rax(key)
    ), 7


def _memory_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for a load/store handler (``mov`` reg <-> [base+disp]).

    The base value is read from its frame slot (so rsp resolves to the captured
    original rsp, and any base updated earlier in the run is seen at its current
    value), the signed displacement is added, and the qword/dword is moved. A
    32-bit load zero-extends, matching x86-64. ``mov`` sets no flags, so the
    captured-flags slot is untouched.
    """
    kind, width_text = handler_key.split("_")
    width = int(width_text)
    body, advance = _mem_address_asm(False, key, key_dword)
    if kind == "load":
        load = "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
        body += load + "  mov qword ptr [rsp+r8*8], rax\n"
    elif width == 64:
        body += "  mov rax, qword ptr [rsp+r8*8]\n  mov qword ptr [r10], rax\n"
    else:
        body += "  mov eax, dword ptr [rsp+r8*8]\n  mov dword ptr [r10], eax\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _riprel_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for a rip-relative load/store handler.

    The target is recomputed as bytecode-base (r15) plus the stored signed
    offset, so it reaches the same global the original ``[rip+disp]`` did and
    stays correct under rebasing (the global and the VM share one image).
    """
    _, sub, width_text = handler_key.split("_")
    width = int(width_text)
    body, advance = _mem_address_asm(True, key, key_dword)
    if sub == "load":
        load = "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
        body += load + "  mov qword ptr [rsp+r8*8], rax\n"
    elif width == 64:
        body += "  mov rax, qword ptr [rsp+r8*8]\n  mov qword ptr [r10], rax\n"
    else:
        body += "  mov eax, dword ptr [rsp+r8*8]\n  mov dword ptr [r10], eax\n"
    return body + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _cmp_memory_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for ``cmp reg, [mem]`` (computes the address, then compares).

    The memory address comes from a frame-slot base plus displacement
    (``cmpmem``) or the bytecode base plus a stored offset (``cmpriprel``). The
    real ``cmp`` sets the flags, which are captured into the flags slot exactly
    like the register/immediate compare handlers.
    """
    parts = handler_key.split("_")
    riprel = parts[0] == "cmpriprel"
    width = int(parts[-1])
    body, advance = _mem_address_asm(riprel, key, key_dword)
    if width == 64:
        body += "  mov r9, qword ptr [rsp+r8*8]\n  cmp r9, qword ptr [r10]\n"
    else:
        body += "  mov r9d, dword ptr [rsp+r8*8]\n  cmp r9d, dword ptr [r10]\n"
    return body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _op_memdst_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for ``<op> [mem], reg`` (memory is the read-modify-write
    destination, the register is the source).

    The address is computed with the shared prologue, the register value is read
    from its slot, and the real arithmetic is applied directly against memory
    (which both reads and writes it), capturing the flags.
    """
    parts = handler_key.split("_")
    riprel = parts[0] == "opmemdstrip"
    mnemonic, width = parts[1], int(parts[2])
    body, advance = _mem_address_asm(riprel, key, key_dword)
    if width == 64:
        body += f"  mov r9, qword ptr [rsp+r8*8]\n  {mnemonic} qword ptr [r10], r9\n"
    else:
        body += f"  mov r9d, dword ptr [rsp+r8*8]\n  {mnemonic} dword ptr [r10], r9d\n"
    return body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _movx_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for ``movzx/movsx reg, byte|word [base+disp]``.

    The address is computed with the shared prologue, then the byte or word is
    zero- or sign-extended into the destination slot. movzx always zero-extends
    the same regardless of destination width; movsx's extension target depends
    on whether the destination is 32- or 64-bit. movzx/movsx set no flags.
    """
    _, ext, src_size_text, dst_width_text = handler_key.split("_")
    body, advance = _mem_address_asm(False, key, key_dword)
    return body + _movx_extend_asm(ext, int(src_size_text), int(dst_width_text), advance)


def _movx_extend_asm(ext: str, src_size: int, dst_width: int, advance: int) -> str:
    """The extend-from-[r10]-into-the-slot tail shared by the movzx/movsx handlers."""
    size_word = "byte" if src_size == 8 else "word"
    if ext == "z":
        load = f"  movzx eax, {size_word} ptr [r10]\n"
    elif dst_width == 64:
        load = f"  movsx rax, {size_word} ptr [r10]\n"
    else:
        load = f"  movsx eax, {size_word} ptr [r10]\n"
    return load + f"  mov qword ptr [rsp+r8*8], rax\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _movx_indexed_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for ``movzx/movsx reg, byte|word [base+index*scale+disp]``."""
    _, ext, src_size_text, dst_width_text = handler_key.split("_")
    body, advance = _indexed_address_asm(key, key_dword)
    return body + _movx_extend_asm(ext, int(src_size_text), int(dst_width_text), advance)


def _incdec_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for ``inc reg`` / ``dec reg``.

    The real inc/dec is applied to the register slot so the carry flag is
    preserved (inc/dec leave CF untouched, unlike add/sub by one), and the
    remaining flags are captured. A 32-bit form zero-extends.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
    # Reload the program's captured flags so inc/dec preserves the program's CF
    # (the interpreter's own carry flag is unrelated), then run the real op.
    body += f"  push qword ptr [rsp+{_FLAGS_OFFSET}]\n  popfq\n"
    if width == 64:
        body += f"  {mnemonic} qword ptr [rsp+r8*8]\n"
    else:
        body += f"  mov eax, dword ptr [rsp+r8*8]\n  {mnemonic} eax\n  mov qword ptr [rsp+r8*8], rax\n"
    return body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, 2\n  jmp vm_dispatch\n"


def _indexed_address_asm(key: int, key_dword: str) -> tuple[str, int]:
    """Shared head of every indexed memory handler: decrypt the register slot
    into r8 and compute ``base + index*scale + disp`` into r10.

    The index is read from its slot and shifted by the encoded scale log2, then
    the base and displacement are added. Returns the assembly and the rsi
    advance (the bytecode item width).
    """
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
        f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
        f"  movzx r11d, byte ptr [rsi+3]\n  xor r11b, {key}\n"
        f"  movzx ecx, byte ptr [rsi+4]\n  xor cl, {key}\n"
        f"  mov eax, dword ptr [rsi+5]\n  mov r10d, {key_dword}\n  xor eax, r10d\n  movsxd rax, eax\n"
        "  mov r10, qword ptr [rsp+r11*8]\n  shl r10, cl\n"
        # Fold the base with MBA too (r11 holds the base value), so neither the
        # base nor the displacement add is a literal add. rcx and r11 are free
        # here (the index slot and scale were already consumed).
        "  mov r11, qword ptr [rsp+r9*8]\n" + _mba_add("r11", "rcx", key) + _mba_add("rax", "rcx", key)
    ), 9


def _lea_store_asm(width: int, advance: int) -> str:
    """The store-address-into-slot tail shared by the lea handlers.

    A 32-bit destination truncates the address to its low 32 bits, zero-extended
    into the 64-bit slot (``mov r10d, r10d`` clears the upper half); a 64-bit
    destination stores the full address.
    """
    truncate = "  mov r10d, r10d\n" if width == 32 else ""
    return f"{truncate}  mov qword ptr [rsp+r8*8], r10\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _lea_indexed_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for ``lea reg, [base + index*scale + disp]`` (32- or 64-bit dst).

    The effective address is computed with the shared indexed prologue and
    stored into the destination slot without dereferencing; lea sets no flags.
    """
    width = int(handler_key.split("_")[1])
    body, advance = _indexed_address_asm(key, key_dword)
    return body + _lea_store_asm(width, advance)


def _lea_indexed_nobase_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for ``lea reg, [index*scale + disp]`` (no base, 32- or 64-bit dst).

    Like the indexed prologue but without the base add: the address is
    ``index*scale + disp``. The item has no base-slot byte, so it is one byte
    shorter (size 8). lea sets no flags; a 32-bit destination truncates.
    """
    width = int(handler_key.split("_")[1])
    body = (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
        f"  movzx r11d, byte ptr [rsi+2]\n  xor r11b, {key}\n"
        f"  movzx ecx, byte ptr [rsi+3]\n  xor cl, {key}\n"
        f"  mov eax, dword ptr [rsi+4]\n  mov r10d, {key_dword}\n  xor eax, r10d\n  movsxd rax, eax\n"
        "  mov r10, qword ptr [rsp+r11*8]\n  shl r10, cl\n" + _mba_add_r10_rax(key)
    )
    return body + _lea_store_asm(width, 8)


def _op_mem_indexed_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for ``<op> reg, [base + index*scale + disp]`` (reg is source
    and destination; memory is the scaled-index source).

    The address is computed with the shared indexed prologue, the register value
    is read from its slot, the real arithmetic is applied against memory, the
    result is written back, and the flags are captured.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    body, advance = _indexed_address_asm(key, key_dword)
    if width == 64:
        body += f"  mov r9, qword ptr [rsp+r8*8]\n  {mnemonic} r9, qword ptr [r10]\n  mov qword ptr [rsp+r8*8], r9\n"
    else:
        body += f"  mov r9d, dword ptr [rsp+r8*8]\n  {mnemonic} r9d, dword ptr [r10]\n  mov qword ptr [rsp+r8*8], r9\n"
    return body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _lea_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for ``lea reg, [base+disp]`` / ``lea reg, [rip+disp]``.

    The effective address is computed exactly like a memory handler, but it is
    stored into the destination slot instead of being dereferenced; lea sets no
    flags. A 32-bit destination truncates the address to its low 32 bits.
    """
    sub, width_text = handler_key.split("_")
    body, advance = _mem_address_asm(sub == "learip", key, key_dword)
    return body + _lea_store_asm(int(width_text), advance)


def _op_memory_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for ``<op> reg, [mem]`` (reg is source and destination).

    The address is computed like the compare-with-memory handler; the register
    value is read from its slot, the real arithmetic is applied against memory,
    the result is written back to the slot (a 32-bit op zero-extends), and the
    flags are captured.
    """
    parts = handler_key.split("_")
    riprel = parts[0] == "opriprel"
    mnemonic, width = parts[1], int(parts[2])
    body, advance = _mem_address_asm(riprel, key, key_dword)
    if width == 64:
        body += f"  mov r9, qword ptr [rsp+r8*8]\n  {mnemonic} r9, qword ptr [r10]\n  mov qword ptr [rsp+r8*8], r9\n"
    else:
        body += f"  mov r9d, dword ptr [rsp+r8*8]\n  {mnemonic} r9d, dword ptr [r10]\n  mov qword ptr [rsp+r8*8], r9\n"
    return body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _compare_handler_asm(handler_key: str, key: int, key_qword: str, key_dword: str) -> str:
    """Assembly body for a cmp/test handler (sets and captures flags only)."""
    mnemonic, mode, width_text = handler_key.split("_")
    width = int(width_text)
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
    if mode == "i" and width == 64:
        body += f"  mov rax, qword ptr [rsi+2]\n  mov r10, {key_qword}\n  xor rax, r10\n  mov r9, qword ptr [rsp+r8*8]\n  {mnemonic} r9, rax\n"
        advance = 10
    elif mode == "i":
        body += f"  mov eax, dword ptr [rsi+2]\n  mov r11d, {key_dword}\n  xor eax, r11d\n  mov r9d, dword ptr [rsp+r8*8]\n  {mnemonic} r9d, eax\n"
        advance = 6
    else:
        body += f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
        if width == 64:
            body += f"  mov rax, qword ptr [rsp+r9*8]\n  mov r10, qword ptr [rsp+r8*8]\n  {mnemonic} r10, rax\n"
        else:
            body += f"  mov eax, dword ptr [rsp+r9*8]\n  mov r10d, dword ptr [rsp+r8*8]\n  {mnemonic} r10d, eax\n"
        advance = 3
    return body + f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, {advance}\n  jmp vm_dispatch\n"


def _shift_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for a shl/shr/sar handler (count is an immediate in cl)."""
    mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n" f"  movzx ecx, byte ptr [rsi+2]\n  xor cl, {key}\n"
    if width == 64:
        body += f"  mov rax, qword ptr [rsp+r8*8]\n  {mnemonic} rax, cl\n"
    else:
        body += f"  mov eax, dword ptr [rsp+r8*8]\n  {mnemonic} eax, cl\n"
    return (
        body
        + f"  mov qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _imul_handler_asm(handler_key: str, key: int) -> str:
    """Assembly body for a two-operand register imul handler."""
    width = int(handler_key.split("_")[1])
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n" f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
    if width == 64:
        body += "  mov rax, qword ptr [rsp+r8*8]\n  imul rax, qword ptr [rsp+r9*8]\n"
    else:
        body += "  mov eax, dword ptr [rsp+r8*8]\n  imul eax, dword ptr [rsp+r9*8]\n"
    return (
        body
        + f"  mov qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, 3\n  jmp vm_dispatch\n"
    )


def _push_handler_asm(key: int, rsp_off: int) -> str:
    """Assembly body for ``push reg`` against the relocated virtual stack.

    The program's rsp lives in a frame slot (relocated below the VM frame at
    entry); decrement it by 8 and write the register value there. push sets no
    flags.
    """
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
        "  mov rax, qword ptr [rsp+r8*8]\n"
        f"  mov r9, qword ptr [rsp+{rsp_off}]\n  sub r9, 8\n  mov qword ptr [rsp+{rsp_off}], r9\n"
        "  mov qword ptr [r9], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _pop_handler_asm(key: int, rsp_off: int) -> str:
    """Assembly body for ``pop reg`` against the relocated virtual stack.

    Read the value at the program's rsp BEFORE incrementing it (matching the
    architectural order), then store it into the destination slot. pop sets no
    flags. The destination is never rsp (rejected at decode), so there is no
    aliasing between the slot write and the rsp-slot update.
    """
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
        f"  mov r9, qword ptr [rsp+{rsp_off}]\n  mov rax, qword ptr [r9]\n"
        f"  add r9, 8\n  mov qword ptr [rsp+{rsp_off}], r9\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _rspadj_handler_asm(handler_key: str, key_dword: str, rsp_off: int) -> str:
    """Assembly body for ``add rsp, imm`` / ``sub rsp, imm`` (frame allocation).

    Adjusts the program's relocated rsp slot by a sign-extended imm32. The flags
    are captured for consistency with the other arithmetic handlers; they reflect
    the relocated stack pointer rather than the native one, which is harmless
    because stack-adjustment flags are architecturally dead in compiled code (no
    branch ever consumes them).
    """
    mnemonic = handler_key.split("_")[1]
    return (
        f"  mov eax, dword ptr [rsi+1]\n  mov r11d, {key_dword}\n  xor eax, r11d\n  movsxd rax, eax\n"
        f"  {mnemonic} qword ptr [rsp+{rsp_off}], rax\n"
        f"  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n"
        "  add rsi, 5\n  jmp vm_dispatch\n"
    )


def _mov_from_rsp_handler_asm(key: int, rsp_off: int) -> str:
    """Assembly body for ``mov reg, rsp`` (copy the relocated rsp into a slot)."""
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
        f"  mov rax, qword ptr [rsp+{rsp_off}]\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _mov_to_rsp_handler_asm(key: int, rsp_off: int) -> str:
    """Assembly body for ``mov rsp, reg`` (restore the relocated rsp from a slot)."""
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
        "  mov rax, qword ptr [rsp+r8*8]\n"
        f"  mov qword ptr [rsp+{rsp_off}], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _leave_handler_asm(key: int, rsp_off: int) -> str:
    """Assembly body for ``leave`` (``mov rsp, rbp`` then ``pop rbp``).

    The rbp slot holds the saved frame pointer; rsp is set to it, then the saved
    rbp is popped off the relocated stack and rsp incremented. No flags.
    """
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n"
        "  mov rax, qword ptr [rsp+r8*8]\n"
        f"  mov qword ptr [rsp+{rsp_off}], rax\n"
        "  mov r9, rax\n  mov rax, qword ptr [r9]\n  add r9, 8\n"
        f"  mov qword ptr [rsp+{rsp_off}], r9\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _pushi_handler_asm(key_qword: str, rsp_off: int) -> str:
    """Assembly body for ``push imm`` (sign-extended 64-bit immediate)."""
    return (
        f"  mov rax, qword ptr [rsi+1]\n  mov r10, {key_qword}\n  xor rax, r10\n"
        f"  mov r9, qword ptr [rsp+{rsp_off}]\n  sub r9, 8\n  mov qword ptr [rsp+{rsp_off}], r9\n"
        "  mov qword ptr [r9], rax\n"
        "  add rsi, 9\n  jmp vm_dispatch\n"
    )


def _imul3_handler_asm(handler_key: str, key: int, key_dword: str) -> str:
    """Assembly body for a three-operand ``imul reg, reg, imm`` handler.

    The immediate lives encrypted in the bytecode stream, so the multiply is
    done by a register-form ``imul`` against the decrypted, sign-extended
    immediate rather than a literal imm operand. The result and CF/OF match the
    native three-operand imul (same low-half product, same overflow).
    """
    width = int(handler_key.split("_")[1])
    body = f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n" f"  movzx r9d, byte ptr [rsi+2]\n  xor r9b, {key}\n"
    body += f"  mov eax, dword ptr [rsi+3]\n  mov r11d, {key_dword}\n  xor eax, r11d\n"
    if width == 64:
        body += "  movsxd r10, eax\n  mov rax, qword ptr [rsp+r9*8]\n  imul rax, r10\n"
    else:
        body += "  mov r10d, dword ptr [rsp+r9*8]\n  imul r10d, eax\n  mov rax, r10\n"
    return (
        body
        + f"  mov qword ptr [rsp+r8*8], rax\n  pushfq\n  pop qword ptr [rsp+{_FLAGS_OFFSET}]\n  add rsi, 7\n  jmp vm_dispatch\n"
    )
