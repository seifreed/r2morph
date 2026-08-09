"""Micro-op primitives for the region VM's flag-dead GP arithmetic.

A handler that computes a whole native op in one body (``add`` == the MBA fold in a
single place) is a fingerprint: identify the handler and you have identified the
native instruction. This module breaks that for the flag-dead arithmetic subset by
lowering each such op into a sequence of tiny primitives over a private virtual
operand stack - ``vpush`` the two sources, ``vbinop`` fold the top two, ``vpop`` the
result. The handler set becomes a few reused primitives shared across every native
op, and the operation lives in the bytecode as data-flow through the stack rather
than one op-per-handler.

The stack lives in the interpreter's own frame (pointer word at ``_VSP_OFFSET``,
cells from ``_VSTACK_BASE``); depth never exceeds two per native op (push, push,
fold, pop nets the pointer back to where it started). The fold reuses the shared MBA
builder, so ``vbinop`` still never spells the native operation. Only the flag-dead
subset is lowered here: it sets no flags, so a stack fold that clobbers flags is
free (mirrors the engine's unconditional micro-op lowering, which relies on the same
flags-dead precondition).
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_fold import arith_fold
from r2morph.mutations.code_virtualization_region_compare import compare_compute
from r2morph.mutations.code_virtualization_region_handlers import (
    _FLAGS_OFFSET,
    _VSP_OFFSET,
    _VSTACK_BASE,
    _indexed_address_asm,
    _indexed_address_nobase_asm,
    _mem_address_asm,
    _movx_load_asm,
    _synth_flags_asm,
    _unmask_dword,
    _unmask_qword,
)
from r2morph.mutations.code_virtualization_region_shift import shift_flag_capture_asm

_VSP = hex(_VSP_OFFSET)
_VBASE = hex(_VSTACK_BASE)

# Push the value in rax onto the vstack and bump the depth pointer.
_PUSH_RAX = (
    f"  mov r9, qword ptr [rsp+{_VSP}]\n"
    f"  mov qword ptr [rsp+r9+{_VBASE}], rax\n"
    "  add r9, 8\n"
    f"  mov qword ptr [rsp+{_VSP}], r9\n"
)


def _vpush_handler_asm(key: str) -> str:
    """Read the operand slot's value and push it onto the vstack.

    The single slot operand sits at ``[rsi+1]`` (one field, so no permutation),
    un-masked with the build key and the stream position (r13b).
    """
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  mov rax, qword ptr [rsp+r8*8]\n" + _PUSH_RAX + "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _vpop_handler_asm(key: str) -> str:
    """Pop the top vstack cell into the operand slot and drop the depth pointer."""
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        f"  mov r9, qword ptr [rsp+{_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rax, qword ptr [rsp+r9+{_VBASE}]\n"
        "  mov qword ptr [rsp+r8*8], rax\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _fsave_handler_asm() -> str:
    """Native ``pushfq``: save the virtual RFLAGS onto the vstack.

    The region synthesizes an operation's readable flags into the flags slot (never
    native RFLAGS), so a native ``pushfq`` is modelled as a copy of that slot onto
    the vstack; the matching ``popfq`` (frestore) pops it back. Opcode only - no
    operand byte, so the vIP advances by one. Assumes matched save/restore leaving
    the vstack balanced across the bracket (the flag-preservation idiom); an
    escaping or unmatched use never reaches here because it fails classification.
    """
    return f"  mov rax, qword ptr [rsp+{_FLAGS_OFFSET}]\n" + _PUSH_RAX + "  add rsi, 1\n  jmp vm_dispatch\n"


def _frestore_handler_asm() -> str:
    """Native ``popfq``: restore the virtual RFLAGS from the vstack.

    Pops the cell saved by the matching ``pushfq`` (fsave) back into the flags slot
    and drops the depth pointer. Opcode only - the vIP advances by one."""
    return (
        f"  mov r9, qword ptr [rsp+{_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rax, qword ptr [rsp+r9+{_VBASE}]\n"
        f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], rax\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
        "  add rsi, 1\n  jmp vm_dispatch\n"
    )


def _vpushi_handler_asm(handler_key: str, key_qword: str, key_dword: str) -> str:
    """Decode a width-sized immediate and push it onto the vstack.

    The decode mirrors the single-handler immediate path exactly (width-sized load,
    un-masked by the key broadcast and the r13b broadcast), so value and masking are
    identical. A 32-bit immediate zero-extends into the low half of the 64-bit cell,
    which is all the width-32 fold reads. The immediate is the only field, at
    ``[rsi+1]``.
    """
    width = int(handler_key.split("_")[1])
    if width == 64:
        decode = f"  mov rax, qword ptr [rsi+1]\n  mov r10, {key_qword}\n  xor rax, r10\n" + _unmask_qword("r10", "r11")
        advance = 9
    else:
        decode = f"  mov eax, dword ptr [rsi+1]\n  mov r11d, {key_dword}\n  xor eax, r11d\n" + _unmask_dword("r11")
        advance = 5
    return decode + _PUSH_RAX + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vbinop_handler_asm(handler_key: str, key: str, arith_variant: int = 0) -> str:
    """Pop the top two cells, fold them with the shared MBA builder, push the result.

    The operands were pushed dst-then-src, so the cell below the top is ``a == dst``
    and the top is ``b == src``: pop b into rax, a into r10. ``sub`` negates b first,
    so ``a + (-b) == dst - src``. ``arith_fold`` leaves the result in r10 with no
    literal native op and no flag capture; a 32-bit fold zero-extends the low half.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    body = (
        f"  mov r9, qword ptr [rsp+{_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rax, qword ptr [rsp+r9+{_VBASE}]\n"
        "  sub r9, 8\n"
        f"  mov r10, qword ptr [rsp+r9+{_VBASE}]\n"
    )
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += arith_fold(mnemonic, 0, arith_variant)
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += (
        f"  mov qword ptr [rsp+r9+{_VBASE}], r10\n"
        "  add r9, 8\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
        "  add rsi, 1\n  jmp vm_dispatch\n"
    )
    return body


def _vbinopsynth_handler_asm(handler_key: str, key: str, flag_variant: int = 0, arith_variant: int = 0) -> str:
    """Fold the top two vstack cells AND synthesize the readable flags, then push.

    The flag-live counterpart of ``_vbinop_handler_asm``: where that serves ops whose
    flags are dead, this serves ops whose flags a later branch reads. It reuses the
    same shared compute+synthesize core as the single-handler ``_op_synth_handler_asm``
    (MBA fold, no literal op; branchless RFLAGS synthesis, no ``pushfq``), changing only
    the operand source (popped off the vstack, not loaded from a slot) and the result
    destination (pushed back, not stored to a slot).

    Operands were pushed dst-then-src, so a == dst (below), b == src (top). The synth
    reads a in rbx, b in rbp, the result in r10, and clobbers rax/rcx/r9 (the vstack
    pointer), so the result cell's index is parked in r8 (which the synth preserves)
    across the synthesis before the push writes there.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    # add/sub keep their arithmetic flags; xor/and/or clear CF and OF (logic mode).
    mode = mnemonic if mnemonic in ("add", "sub") else "logic"
    body = (
        f"  mov r9, qword ptr [rsp+{_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rax, qword ptr [rsp+r9+{_VBASE}]\n"
        "  sub r9, 8\n"
        f"  mov r10, qword ptr [rsp+r9+{_VBASE}]\n"
    )
    # Save the originals for the synthesis (a and b before any negation) and park the
    # result cell index in r8, which survives the flag synthesis.
    body += "  mov rbx, r10\n  mov rbp, rax\n  mov r8, r9\n"
    if mnemonic == "sub":
        body += "  neg rax\n"
    body += arith_fold(mnemonic, 0, arith_variant)
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(width, mode, flag_variant)
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    body += (
        f"  mov qword ptr [rsp+r8+{_VBASE}], r10\n"
        "  lea r9, [r8+8]\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
        "  add rsi, 1\n  jmp vm_dispatch\n"
    )
    return body


def _vcmpsynth_handler_asm(
    handler_key: str, key: str, flag_variant: int = 0, arith_variant: int = 0, compare_variant: int = 0
) -> str:
    """Pop the top two vstack cells, synthesize the compare flags, push nothing.

    The flag-only counterpart of ``_vbinopsynth_handler_asm``: ``cmp``/``test`` exist
    only to set the flags a later branch reads, so this folds ``a`` and ``b`` the same
    way but stores no result (net vstack depth -2). ``cmp`` synthesizes the flags of
    ``a - b`` (MBA add after negating b), ``test`` the flags of ``a & b`` (logic mode,
    CF and OF cleared). No literal cmp/test, no ``pushfq``.

    Operands were pushed left-then-right, so a == left (below), b == right (top): pop b
    into rax, a into r10. The post-double-pop stack pointer is written back to its slot
    BEFORE the synthesis, because ``_synth_flags_asm`` clobbers r9.
    """
    _, op, width_text = handler_key.split("_")
    width = int(width_text)
    mode = "sub" if op == "cmp" else "logic"
    body = (
        f"  mov r9, qword ptr [rsp+{_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rax, qword ptr [rsp+r9+{_VBASE}]\n"
        "  sub r9, 8\n"
        f"  mov r10, qword ptr [rsp+r9+{_VBASE}]\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
    )
    # Save the originals for the synthesis (a and b before any negation).
    body += "  mov rbx, r10\n  mov rbp, rax\n"
    # cmp -> flags of a - b (== a + (-b)); test -> flags of a & b. Result is discarded.
    if compare_variant == 0:
        if op == "cmp":
            body += "  neg rax\n" + arith_fold("add", 0, arith_variant)
        else:
            body += arith_fold("and", 0, arith_variant)
    else:
        body += compare_compute(op, 0, arith_variant, compare_variant)
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += _synth_flags_asm(width, mode, flag_variant)
    body += f"  mov qword ptr [rsp+{_FLAGS_OFFSET}], r11\n"
    body += "  add rsi, 1\n  jmp vm_dispatch\n"
    return body


def _vload_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> str:
    """Load ``[base+disp]`` and push the value onto the vstack.

    Reuses the shared MBA-folded address prologue (``_mem_address_asm``), which
    decodes a base+disp operand into the effective address in r10 (and clobbers the
    vstack pointer r9), then reads the qword/dword and pushes it. The register field
    the prologue decodes into r8 is an unused placeholder (the value goes on the
    stack, not into a register). A 32-bit load zero-extends. No flags.
    """
    width = int(handler_key.split("_")[1])
    body, advance = _mem_address_asm(False, key, key_dword, field_perm, addr_variant)
    body += "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
    # The address prologue clobbered r9 (the base slot index), so _PUSH_RAX reloads
    # the vstack pointer from its frame slot before pushing.
    return body + _PUSH_RAX + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vstore_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> str:
    """Pop the top vstack cell and store it to ``[base+disp]``.

    The pop happens first, into rbx (which the address prologue preserves), because
    ``_mem_address_asm`` clobbers the vstack pointer r9. Then the shared prologue
    computes the address into r10 and the value is stored. No flags.
    """
    width = int(handler_key.split("_")[1])
    pop = (
        f"  mov r9, qword ptr [rsp+{_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rbx, qword ptr [rsp+r9+{_VBASE}]\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
    )
    body, advance = _mem_address_asm(False, key, key_dword, field_perm, addr_variant)
    store = "  mov qword ptr [r10], rbx\n" if width == 64 else "  mov dword ptr [r10], ebx\n"
    return pop + body + store + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vstoreidx_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Pop the top vstack cell and store it to ``[base+index*scale+disp]``.

    Mirrors :func:`_vstore_handler_asm` but computes the effective address with the
    shared scaled-index prologue (``_indexed_address_asm``). The pop happens first,
    into rbx (which the prologue preserves), because the prologue clobbers the vstack
    pointer r9. A 32-bit store writes the low dword. No flags.
    """
    width = int(handler_key.split("_")[1])
    pop = (
        f"  mov r9, qword ptr [rsp+{_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rbx, qword ptr [rsp+r9+{_VBASE}]\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
    )
    body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    store = "  mov qword ptr [r10], rbx\n" if width == 64 else "  mov dword ptr [r10], ebx\n"
    return pop + body + store + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vloadidx_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Load ``[base+index*scale+disp]`` and push the value onto the vstack.

    Reuses the shared MBA-folded scaled-index address prologue
    (``_indexed_address_asm``), which decodes the operand into the effective address
    in r10 (and clobbers the vstack pointer r9), then reads the qword/dword and pushes
    it. The register field the prologue decodes into r8 is an unused placeholder (the
    value goes on the stack, not into a register). A 32-bit load zero-extends. No flags.
    """
    width = int(handler_key.split("_")[1])
    body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    body += "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
    # The address prologue clobbered r9 (the base slot index), so _PUSH_RAX reloads
    # the vstack pointer from its frame slot before pushing.
    return body + _PUSH_RAX + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vloadrip_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Load ``[rip+disp]`` (a global) and push the value onto the vstack.

    Identical to :func:`_vload_handler_asm` but the address is bytecode-base-relative
    (``_mem_address_asm(True, ...)`` folds the stored signed offset onto r15, the
    bytecode base). That prologue does not clobber the vstack pointer r9, but
    ``_PUSH_RAX`` reloads it from its frame slot either way. A 32-bit load
    zero-extends. No flags.
    """
    width = int(handler_key.split("_")[1])
    body, advance = _mem_address_asm(True, key, key_dword, field_perm, addr_variant)
    body += "  mov rax, qword ptr [r10]\n" if width == 64 else "  mov eax, dword ptr [r10]\n"
    return body + _PUSH_RAX + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vstorerip_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Pop the top vstack cell and store it to ``[rip+disp]`` (a global).

    Like :func:`_vstore_handler_asm`, the pop happens first into rbx (preserved by
    the address prologue), then ``_mem_address_asm(True, ...)`` computes the
    bytecode-base-relative address into r10 and the value is stored. No flags.
    """
    width = int(handler_key.split("_")[1])
    pop = (
        f"  mov r9, qword ptr [rsp+{_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rbx, qword ptr [rsp+r9+{_VBASE}]\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
    )
    body, advance = _mem_address_asm(True, key, key_dword, field_perm, addr_variant)
    store = "  mov qword ptr [r10], rbx\n" if width == 64 else "  mov dword ptr [r10], ebx\n"
    return pop + body + store + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vlea_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> str:
    """Compute a ``lea`` effective address and push it onto the vstack (no deref).

    Reuses the shared MBA-folded address prologue (base+disp, or bytecode-base
    relative when the key is ``vlearip``), which decodes the operand into r10; a
    following ``vpop`` writes that address to the destination slot. lea sets no
    flags. A 32-bit destination truncates to the low 32 bits, zero-extended, before
    the push. The register field the prologue decodes into r8 is an unused
    placeholder (the address goes on the vstack, not into a register).
    """
    sub, width_text = handler_key.split("_")
    body, advance = _mem_address_asm(sub == "vlearip", key, key_dword, field_perm, addr_variant)
    body += "  mov eax, r10d\n" if int(width_text) == 32 else "  mov rax, r10\n"
    # The address prologue clobbered r9 (the base slot index), so _PUSH_RAX reloads
    # the vstack pointer from its frame slot before pushing.
    return body + _PUSH_RAX + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vleaidx_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> str:
    """Compute a scaled-index ``lea`` address (base+index*scale+disp) and push it.

    Like :func:`_vlea_handler_asm` but with the shared scaled-index prologue; no
    deref, no flags. A 32-bit destination truncates before the push.
    """
    width = int(handler_key.split("_")[1])
    body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    body += "  mov eax, r10d\n" if width == 32 else "  mov rax, r10\n"
    return body + _PUSH_RAX + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vleaidxnb_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Compute a no-base scaled-index ``lea`` address (index*scale+disp) and push it.

    Like :func:`_vleaidx_handler_asm` but the operand carries no base slot byte, so
    the prologue is one byte shorter; no deref, no flags. A 32-bit destination
    truncates before the push.
    """
    width = int(handler_key.split("_")[1])
    body, advance = _indexed_address_nobase_asm(key, key_dword, field_perm, addr_variant)
    body += "  mov eax, r10d\n" if width == 32 else "  mov rax, r10\n"
    return body + _PUSH_RAX + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vmovx_handler_asm(handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0) -> str:
    """Load ``byte|word [base+disp]`` with zero/sign extension and push it.

    The micro-op form of ``movzx/movsx reg, [base+disp]``: the shared address
    prologue computes the effective address into r10, the byte or word is extended
    into rax by the shared load helper, and it is pushed onto the vstack; a following
    ``vpop`` writes it to the destination slot. No flags. The register field the
    prologue decodes into r8 is an unused placeholder (the value goes on the vstack).
    """
    _, ext, src_size_text, dst_width_text = handler_key.split("_")
    body, advance = _mem_address_asm(False, key, key_dword, field_perm, addr_variant)
    body += _movx_load_asm(ext, int(src_size_text), int(dst_width_text))
    # The address prologue clobbered r9 (the base slot index), so _PUSH_RAX reloads
    # the vstack pointer from its frame slot before pushing.
    return body + _PUSH_RAX + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vmovxidx_handler_asm(
    handler_key: str, key: str, key_dword: str, field_perm: int = 0, addr_variant: int = 0
) -> str:
    """Load ``byte|word [base+index*scale+disp]`` with zero/sign extension and push it.

    Like :func:`_vmovx_handler_asm` but with the shared scaled-index address
    prologue; no flags. A following ``vpop`` writes the extended value to the slot.
    """
    _, ext, src_size_text, dst_width_text = handler_key.split("_")
    body, advance = _indexed_address_asm(key, key_dword, field_perm, addr_variant)
    body += _movx_load_asm(ext, int(src_size_text), int(dst_width_text))
    return body + _PUSH_RAX + f"  add rsi, {advance}\n  jmp vm_dispatch\n"


def _vshift_handler_asm(handler_key: str, key: str, shift_variant: int = 0) -> str:
    """Pop the top vstack cell, shift it by the carried count, capture flags, push.

    Lowers a native ``shl``/``shr``/``sar reg, imm``: the shifted register value is
    popped off the stack, the count byte (the only operand, at ``[rsi+1]``, un-masked
    with the key and the stream position) goes into cl, the CPU runs the real shift
    (which masks the count to the operand width, faithful to the native op), and the
    flags it sets are captured into the flags slot exactly as the single-handler form
    did. A 32-bit shift operates on eax, zero-extending the cell. The vstack pointer
    (r9) is untouched by the shift and the flag capture, so the single-pop/single-push
    bookkeeping mirrors the other primitives.
    """
    _, mnemonic, width_text = handler_key.split("_")
    width = int(width_text)
    body = (
        f"  mov r9, qword ptr [rsp+{_VSP}]\n"
        "  sub r9, 8\n"
        f"  mov rax, qword ptr [rsp+r9+{_VBASE}]\n"
        f"  movzx ecx, byte ptr [rsi+1]\n  xor cl, {key}\n  xor cl, r13b\n"
    )
    body += f"  {mnemonic} rax, cl\n" if width == 64 else f"  {mnemonic} eax, cl\n"
    body += shift_flag_capture_asm(shift_variant, _FLAGS_OFFSET)
    body += (
        f"  mov qword ptr [rsp+r9+{_VBASE}], rax\n"
        "  add r9, 8\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
        "  add rsi, 2\n  jmp vm_dispatch\n"
    )
    return body
