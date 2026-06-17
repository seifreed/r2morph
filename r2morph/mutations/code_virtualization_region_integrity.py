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

# A free frame slot above the captured RFLAGS (0x80) and below the preserved
# red zone (0x100); see code_virtualization_region_handlers._FRAME_SIZE.
_CHECKSUM_OFFSET = 0x88

_ROTATE = 3  # left-rotate applied to the accumulator after each byte


def checksum_prologue_asm(
    start_label: str = "vm_entry", end_label: str = "vm_table", slot: int = _CHECKSUM_OFFSET, tag: str = ""
) -> str:
    """Assembly that computes the runtime checksum over ``[start_label, end_label)``.

    Runs at ``vm_entry`` after every GP register is spilled to the frame, so it
    is free to clobber rcx/rdx/rdi; the result is stored to the ``slot`` byte of
    the frame, which the dispatch reads. ``tag`` makes the loop labels unique
    when several interpreters share one blob.
    """
    loop = f"chk_loop{tag}"
    done = f"chk_done{tag}"
    return (
        "  xor edx, edx\n"
        f"  lea rdi, [rip+{start_label}]\n"
        f"  lea rcx, [rip+{end_label}]\n"
        f"{loop}:\n"
        "  cmp rdi, rcx\n"
        f"  jae {done}\n"
        "  add dl, byte ptr [rdi]\n"
        f"  rol dl, {_ROTATE}\n"
        "  inc rdi\n"
        f"  jmp {loop}\n"
        f"{done}:\n"
        f"  mov byte ptr [rsp+{slot}], dl\n"
    )


def compute_build_checksum(code: bytes) -> int:
    """The expected runtime checksum of ``code`` (must mirror the asm loop)."""
    acc = 0
    for byte in code:
        acc = (acc + byte) & 0xFF
        acc = ((acc << _ROTATE) | (acc >> (8 - _ROTATE))) & 0xFF
    return acc
