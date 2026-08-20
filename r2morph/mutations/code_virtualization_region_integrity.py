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
# not a fixed linear scan an automated devirtualizer can match and strip. Each
# build walks four-byte blocks in a seeded local permutation; the final partial
# block uses guarded reads in that same order.
_CHECKSUM_OPS = ("add", "xor", "sub")
_CHECKSUM_ROTATES = ("rol", "ror")
_CHECKSUM_PERMUTATIONS = (
    (0, 1, 2, 3),
    (0, 2, 3, 1),
    (1, 3, 0, 2),
    (2, 0, 3, 1),
    (2, 3, 1, 0),
    (3, 1, 0, 2),
)


def _checksum_step(variant: int) -> tuple[str, str, int]:
    """Decode ``variant`` into (mix op, rotate direction, rotate amount 1..7)."""
    amount = (variant % 7) + 1
    op = _CHECKSUM_OPS[(variant // 7) % len(_CHECKSUM_OPS)]
    rotate = _CHECKSUM_ROTATES[(variant // 21) % len(_CHECKSUM_ROTATES)]
    return op, rotate, amount


def _checksum_bytes(code: bytes, variant: int) -> Iterator[int]:
    """Bytes of ``code`` in this build's block-permutation traversal order."""
    permutation = _CHECKSUM_PERMUTATIONS[(variant // 84) % len(_CHECKSUM_PERMUTATIONS)]
    for offset in range(0, len(code), 4):
        block = code[offset : offset + 4]
        for index in permutation:
            if index < len(block):
                yield block[index]


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
    tail = f"chk_tail{tag}"
    done = f"chk_done{tag}"
    permutation = _CHECKSUM_PERMUTATIONS[(variant // 84) % len(_CHECKSUM_PERMUTATIONS)]
    full_mix = "".join(f"  {op} dl, byte ptr [rdi+{index}]\n  {rotate} dl, {amount}\n" for index in permutation)
    tail_mix = "".join(
        f"  lea r8, [rdi+{index}]\n"
        f"  cmp r8, rcx\n"
        f"  jae chk_skip{tag}_{index}\n"
        f"  {op} dl, byte ptr [r8]\n"
        f"  {rotate} dl, {amount}\n"
        f"chk_skip{tag}_{index}:\n"
        for index in permutation
    )
    return "".join(
        [
            "  xor edx, edx\n",
            f"  lea rdi, [rip+{start_label}]\n",
            f"  lea rcx, [rip+{end_label}]\n",
            "  mov r8, rcx\n",
            "  sub r8, rdi\n",
            "  cmp r8, 4\n",
            f"  jb {tail}\n",
            f"{loop}:\n",
            full_mix,
            "  add rdi, 4\n",
            "  mov r8, rcx\n",
            "  sub r8, rdi\n",
            "  cmp r8, 4\n",
            f"  jae {loop}\n",
            f"{tail}:\n",
            tail_mix,
            f"{done}:\n",
            f"  mov byte ptr [rsp+{slot}], dl\n",
        ]
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
