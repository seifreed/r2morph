"""Runtime self-checksum that makes the VM's own code load-bearing.

The interpreter rolls a one-byte bootstrap checksum over its entry code, then
replaces it with a full-code checksum after bootstrap probes finish. The encoder
pre-biases every opcode byte with the *expected* full checksum (computed over the
finished, assembled interpreter), so a legitimate build decodes correctly while
any post-build patch of an interpreter byte changes the runtime checksum, every
opcode then misdecodes, the dispatch bounds-guard sends control to the early exit,
and the virtualized body never runs - an observable divergence. There is no
comparison or conditional branch to neutralize: the checksum *is* key material.

The checksummed range is the interpreter code only, ``[start_label,
end_label)`` - the dispatch table and the bytecode are excluded, so the
expected checksum does not depend on values written after assembly (the table
is XOR-encrypted in place) and there is no circular dependency.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

# A free frame slot above the captured RFLAGS (0x80) and below the preserved
# red zone (0x100); see code_virtualization_region_handlers._FRAME_SIZE.
_CHECKSUM_OFFSET = 0x88

# The accumulate step and traversal order are polymorphic so the checksum loop is
# not a fixed linear scan an automated devirtualizer can match and strip. Builds
# select either a seeded four-byte block permutation or a byte-at-a-time walk.
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


@dataclass(frozen=True)
class ChecksumPrologue:
    variant: int
    start_label: str = "vm_entry"
    end_label: str = "vm_table"
    slot: int = _CHECKSUM_OFFSET
    bytewise: bool = False
    label_prefix: str = ""


def _checksum_step(variant: int) -> tuple[str, str, int]:
    """Decode ``variant`` into (mix op, rotate direction, rotate amount 1..7)."""
    amount = (variant % 7) + 1
    op = _CHECKSUM_OPS[(variant // 7) % len(_CHECKSUM_OPS)]
    rotate = _CHECKSUM_ROTATES[(variant // 21) % len(_CHECKSUM_ROTATES)]
    return op, rotate, amount


def _checksum_bytes(code: bytes, variant: int, bytewise: bool = False) -> Iterator[int]:
    """Bytes of ``code`` in this build's checksum traversal order."""
    if bytewise:
        yield from code
        return
    permutation = _CHECKSUM_PERMUTATIONS[(variant // 84) % len(_CHECKSUM_PERMUTATIONS)]
    for offset in range(0, len(code), 4):
        block = code[offset : offset + 4]
        for index in permutation:
            if index < len(block):
                yield block[index]


def checksum_prologue_asm(
    variant: int | ChecksumPrologue,
    start_label: str = "vm_entry",
    end_label: str = "vm_table",
    slot: int = _CHECKSUM_OFFSET,
    bytewise: bool = False,
) -> str:
    """Assembly that computes the runtime checksum over ``[start_label, end_label)``.

    Runs after the required register spill or bootstrap transition, so it is free
    to clobber rcx/rdx/rdi; the result is stored to the ``slot`` byte of the frame,
    which the bootstrap or dispatch reads. ``variant`` selects the polymorphic mix
    step and traversal order; ``bytewise`` selects the alternate byte-at-a-time
    traversal.
    """
    spec = (
        variant
        if isinstance(variant, ChecksumPrologue)
        else ChecksumPrologue(variant, start_label, end_label, slot, bytewise)
    )
    op, rotate, amount = _checksum_step(spec.variant)
    loop = f"{spec.label_prefix}chk_loop"
    tail = f"{spec.label_prefix}chk_tail"
    done = f"{spec.label_prefix}chk_done"
    if spec.bytewise:
        return "".join(
            [
                "  xor edx, edx\n",
                f"  lea rdi, [rip+{spec.start_label}]\n",
                f"  lea rcx, [rip+{spec.end_label}]\n",
                "  cmp rdi, rcx\n",
                f"  jae {done}\n",
                f"{loop}:\n",
                f"  {op} dl, byte ptr [rdi]\n",
                f"  {rotate} dl, {amount}\n",
                "  inc rdi\n",
                "  cmp rdi, rcx\n",
                f"  jb {loop}\n",
                f"{done}:\n",
                f"  mov byte ptr [rsp+{spec.slot}], dl\n",
            ]
        )
    permutation = _CHECKSUM_PERMUTATIONS[(spec.variant // 84) % len(_CHECKSUM_PERMUTATIONS)]
    full_mix = "".join(f"  {op} dl, byte ptr [rdi+{index}]\n  {rotate} dl, {amount}\n" for index in permutation)
    tail_mix = "".join(
        f"  lea r8, [rdi+{index}]\n"
        f"  cmp r8, rcx\n"
        f"  jae {spec.label_prefix}chk_skip_{index}\n"
        f"  {op} dl, byte ptr [r8]\n"
        f"  {rotate} dl, {amount}\n"
        f"{spec.label_prefix}chk_skip_{index}:\n"
        for index in permutation
    )
    return "".join(
        [
            "  xor edx, edx\n",
            f"  lea rdi, [rip+{spec.start_label}]\n",
            f"  lea rcx, [rip+{spec.end_label}]\n",
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
            f"  mov byte ptr [rsp+{spec.slot}], dl\n",
        ]
    )


def compute_build_checksum(code: bytes, variant: int, bytewise: bool = False) -> int:
    """The expected runtime checksum of ``code`` (must mirror the asm loop)."""
    op, rotate, amount = _checksum_step(variant)
    acc = 0
    for byte in _checksum_bytes(code, variant, bytewise):
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
