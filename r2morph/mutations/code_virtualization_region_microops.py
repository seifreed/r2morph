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

from r2morph.mutations.code_virtualization_mba import _op_mba_compute
from r2morph.mutations.code_virtualization_region_handlers import (
    _VSP_OFFSET,
    _VSTACK_BASE,
    _unmask_dword,
    _unmask_qword,
)

_VSP = hex(_VSP_OFFSET)
_VBASE = hex(_VSTACK_BASE)

# Push the value in rax onto the vstack and bump the depth pointer.
_PUSH_RAX = (
    f"  mov r9, qword ptr [rsp+{_VSP}]\n"
    f"  mov qword ptr [rsp+r9+{_VBASE}], rax\n"
    "  add r9, 8\n"
    f"  mov qword ptr [rsp+{_VSP}], r9\n"
)


def _vpush_handler_asm(key: int) -> str:
    """Read the operand slot's value and push it onto the vstack.

    The single slot operand sits at ``[rsi+1]`` (one field, so no permutation),
    un-masked with the build key and the stream position (r13b).
    """
    return (
        f"  movzx r8d, byte ptr [rsi+1]\n  xor r8b, {key}\n  xor r8b, r13b\n"
        "  mov rax, qword ptr [rsp+r8*8]\n" + _PUSH_RAX + "  add rsi, 2\n  jmp vm_dispatch\n"
    )


def _vpop_handler_asm(key: int) -> str:
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


def _vbinop_handler_asm(handler_key: str, key: int) -> str:
    """Pop the top two cells, fold them with the shared MBA builder, push the result.

    The operands were pushed dst-then-src, so the cell below the top is ``a == dst``
    and the top is ``b == src``: pop b into rax, a into r10. ``sub`` negates b first,
    so ``a + (-b) == dst - src``. ``_op_mba_compute`` leaves the result in r10 with no
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
    body += _op_mba_compute(mnemonic, key)
    if width == 32:
        body += "  mov r10d, r10d\n"
    body += (
        f"  mov qword ptr [rsp+r9+{_VBASE}], r10\n"
        "  add r9, 8\n"
        f"  mov qword ptr [rsp+{_VSP}], r9\n"
        "  add rsi, 1\n  jmp vm_dispatch\n"
    )
    return body
