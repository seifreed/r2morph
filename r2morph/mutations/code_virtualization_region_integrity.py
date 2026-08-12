"""Runtime self-checksum that makes the VM's own code load-bearing.

The interpreter rolls a one-byte checksum over its own machine code at entry
and folds it into the opcode decryption. The encoder pre-biases every opcode
byte with the *expected* checksum (computed over the finished, assembled
interpreter), so a legitimate build decodes correctly while any post-build
patch of an interpreter byte changes the runtime checksum, every opcode then
misdecodes, the dispatch bounds-guard sends control to the early exit, and the
virtualized body never runs - an observable divergence. There is no comparison
or conditional branch to neutralize: the checksum *is* key material.

The checksummed range is the interpreter code only, ``[start_label,
end_label)`` - the dispatch table and the bytecode are excluded, so the
expected checksum does not depend on values written after assembly (the table
is XOR-encrypted in place) and there is no circular dependency.
"""

from __future__ import annotations

from collections.abc import Iterator

# A free frame slot above the captured RFLAGS (0x80) and below the preserved
# red zone (0x100); see code_virtualization_region_handlers._FRAME_SIZE.
_CHECKSUM_OFFSET = 0x88

# The accumulate step and traversal order are polymorphic so the checksum loop is
# not a fixed linear scan an automated devirtualizer can match and strip. Every
# iteration alternates between the range's low and high ends, converging inward;
# the variant selects which end is read first as well as the mix and rotate.
_CHECKSUM_OPS = ("add", "xor", "sub")
_CHECKSUM_ROTATES = ("rol", "ror")


def _checksum_step(variant: int) -> tuple[str, str, int]:
    """Decode ``variant`` into (mix op, rotate direction, rotate amount 1..7)."""
    amount = (variant % 7) + 1
    op = _CHECKSUM_OPS[(variant // 7) % len(_CHECKSUM_OPS)]
    rotate = _CHECKSUM_ROTATES[(variant // 21) % len(_CHECKSUM_ROTATES)]
    return op, rotate, amount


def _checksum_bytes(code: bytes, variant: int) -> Iterator[int]:
    """Bytes of ``code`` in this build's alternating-ends traversal order."""
    low, high = 0, len(code) - 1
    high_first = bool((variant // 42) & 1)
    while low <= high:
        yield code[high] if high_first else code[low]
        if low != high:
            yield code[low] if high_first else code[high]
        low += 1
        high -= 1


def checksum_prologue_asm(
    variant: int,
    start_label: str = "vm_entry",
    end_label: str = "vm_table",
    slot: int = _CHECKSUM_OFFSET,
    tag: str = "",
) -> str:
    """Assembly that computes the runtime checksum over ``[start_label, end_label)``.

    Runs at ``vm_entry`` after every GP register is spilled to the frame, so it
    is free to clobber rcx/rdx/rdi; the result is stored to the ``slot`` byte of
    the frame, which the dispatch reads. ``variant`` selects the polymorphic mix
    step and traversal order; ``tag`` makes the loop labels unique when several
    interpreters share one blob.
    """
    op, rotate, amount = _checksum_step(variant)
    loop = f"chk_loop{tag}"
    done = f"chk_done{tag}"
    first, second = ("rcx", "rdi") if (variant // 42) & 1 else ("rdi", "rcx")
    first_mix = f"  {op} dl, byte ptr [{first}]\n  {rotate} dl, {amount}\n"
    second_mix = f"  {op} dl, byte ptr [{second}]\n  {rotate} dl, {amount}\n"
    return (
        "  xor edx, edx\n"
        f"  lea rdi, [rip+{start_label}]\n"
        f"  lea rcx, [rip+{end_label}]\n"
        "  cmp rdi, rcx\n"
        f"  jae {done}\n"
        "  dec rcx\n"
        f"{loop}:\n"
        "  cmp rdi, rcx\n"
        f"  ja {done}\n" + first_mix + "  cmp rdi, rcx\n" + f"  je {done}\n" + second_mix + "  inc rdi\n"
        "  dec rcx\n"
        f"  jmp {loop}\n"
        f"{done}:\n"
        f"  mov byte ptr [rsp+{slot}], dl\n"
    )


def compute_build_checksum(code: bytes, variant: int) -> int:
    """The expected runtime checksum of ``code`` (must mirror the asm loop)."""
    op, rotate, amount = _checksum_step(variant)
    acc = 0
    for byte in _checksum_bytes(code, variant):
        if op == "add":
            acc = (acc + byte) & 0xFF
        elif op == "sub":
            acc = (acc - byte) & 0xFF
        else:
            acc ^= byte
        if rotate == "rol":
            acc = ((acc << amount) | (acc >> (8 - amount))) & 0xFF
        else:
            acc = ((acc >> amount) | (acc << (8 - amount))) & 0xFF
    return acc
