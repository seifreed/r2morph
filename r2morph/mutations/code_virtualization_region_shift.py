"""Per-build shift flag-capture personality for the region VM (semantic ISA axis).

The shl/shr/sar handlers must record the CPU flags their native shift sets. The
canonical spelling pushes the whole RFLAGS (``pushfq``) and pops it into the flags
slot. This module forks that capture into an equivalent alternate that rebuilds the
same readable condition flags (CF, PF, ZF, SF, OF) with ``lahf`` + ``seto`` - a
different instruction idiom producing the same flag image the jcc handlers read
(the synth path already stores only those bits), so two builds capture shift flags
with distinct assembly.

Unlike a hand-synthesis of shift flags, both spellings read the *real* CPU flags,
so every count edge matches the native op bit-for-bit: the architecturally
undefined OF at count > 1, and the count masked to zero (a no-op that leaves the
flags whatever the handler's own operand loads left) both capture exactly what
``pushfq`` would. That is why this axis can ship a proven-equivalent variant where a
from-scratch flag synthesis could not.

``shift_variant`` 0 is the canonical ``pushfq`` spelling (byte-identical to the
pre-feature output). The alternate preserves rax (the shifted result) across the
``lahf`` that overwrites ah, and uses r10/r11 as scratch - both free in every shift
handler at the capture point.
"""

from __future__ import annotations

# Width in bits of shift_variant: one alternate capture idiom beyond the canonical.
SHIFT_VARIANT_BITS = 1


def shift_flag_capture_asm(variant: int, flags_offset: int) -> str:
    """Capture the current CPU flags into the flags slot; ``variant`` picks the idiom.

    variant 0 pushes/pops the full RFLAGS (canonical). A non-zero variant rebuilds
    the readable flags with ``lahf`` (CF/PF/AF/ZF/SF) and ``seto`` (OF) into the same
    slot bits the jcc handlers read. Must run immediately after the shift, before any
    flag-clobbering instruction (a ``mov`` in between preserves the flags).
    """
    if variant % 2 == 0:
        return f"  pushfq\n  pop qword ptr [rsp+{flags_offset}]\n"
    # rax holds the shifted result; lahf overwrites ah, so save and restore it. The
    # low RFLAGS byte is exactly ah's layout (CF/PF/AF/ZF/SF at bits 0/2/4/6/7); OF is
    # bit 11, taken from seto. Other bits are irrelevant - no jcc handler reads them.
    return (
        "  mov r10, rax\n"
        "  lahf\n"
        "  seto r11b\n"
        "  movzx r11d, r11b\n"
        "  shl r11d, 11\n"
        "  movzx eax, ah\n"
        "  or r11, rax\n"
        f"  mov qword ptr [rsp+{flags_offset}], r11\n"
        "  mov rax, r10\n"
    )
