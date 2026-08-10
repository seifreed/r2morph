"""Post-process a region interpreter's handler assembly to encrypt the register file.

The region VM keeps the program's 16 GP registers in a flat frame array at
``[rsp + slot*8]`` (the relocated program rsp included, at ``[rsp + rsp_off]``).
Stored in the clear, a decompiler reads that array as a plain register context.

This module ciphers it in one place instead of at every handler site: it rewrites
each register-slot ``mov`` in the generated handler assembly to XOR the value with
the self-checksum key (the same ``[rsp + _KEY_QWORD_SLOT]`` broadcast the operand
cipher materializes at entry) - decrypt right after every slot load, encrypt right
before every slot store. Because the key byte is uniform across all eight lanes,
the XOR at the ``mov``'s own width decrypts/encrypts correctly for byte/word/dword/
qword accesses with no sub-width merge.

The store is wrapped on both sides (``xor; mov; xor``) so the source register keeps
its plaintext value for any later use, and so the transform is oblivious to
liveness. The encrypting XOR does set flags, so a handler whose flags a branch
later reads must already have captured them (``pushfq``) *before* its slot store;
the flag-carrying arithmetic handlers are written that way (store after capture),
which is the one ordering constraint this pass relies on.

Only register-file slots are touched: the match requires the ``*8`` scaled index
(dynamic data slots) or the exact ``rsp_off`` displacement (the relocated program
rsp), so the fixed-offset frame words - captured RFLAGS, checksum, the key slots,
the virtual operand stack ``[rsp + r + VBASE]`` (ciphered separately) - never match.
"""

from __future__ import annotations

import re

# Must match code_virtualization_region_handlers._KEY_QWORD_SLOT and _FLAGS_OFFSET.
_KEY_QWORD_SLOT = 0x208
_GP_ARRAY_END = 0x80  # the 16 GP slots occupy [0x00, 0x80); the flags word starts here

# A register-file slot displacement: a scaled register index (dynamic operand - the
# index register may be any GP register, since the per-instance renamer rewrites the
# scratch pool to named registers like rax/rbx) or a plain decimal below the GP array
# end (the fixed spill/reload/rsp slot offsets, emitted as decimals). Fixed frame
# words - flags 0x80, checksum, the key slots, the virtual stack ``[rsp+r+0x288]`` -
# are all at or above 0x80, or carry a ``r+`` term or a hex offset, so none match.
# Whitespace around ``+`` and ``*`` is optional: the GP handlers emit ``[rsp+r8*8]``,
# the FP handlers ``[rsp + r9*8]``.
_DISP = r"(?:\w+\s*\*\s*8|\d+)"
_READ_RE = re.compile(rf"^(\s*)mov (\w+), (qword|dword|word|byte) ptr \[rsp\s*\+\s*({_DISP})\]\s*$")
_WRITE_RE = re.compile(rf"^(\s*)mov ((?:qword|dword|word|byte) ptr \[rsp\s*\+\s*({_DISP})\]), (\w+)\s*$")


def _key(width: str) -> str:
    return f"{width} ptr [rsp+{_KEY_QWORD_SLOT}]"


def _is_slot(disp: str) -> bool:
    """A scaled index is always a slot; a fixed decimal is one only below the array end."""
    return "*" in disp or int(disp) < _GP_ARRAY_END


def cipher_register_slots(asm: str) -> str:
    """Return ``asm`` with every GP register-slot load decrypted and store encrypted."""
    out: list[str] = []
    for line in asm.split("\n"):
        read = _READ_RE.match(line)
        if read and _is_slot(read.group(4)):
            indent, reg, width, _ = read.groups()
            out.append(line)
            out.append(f"{indent}xor {reg}, {_key(width)}")
            continue
        write = _WRITE_RE.match(line)
        if write and _is_slot(write.group(3)):
            indent, dest, _, reg = write.groups()
            width = dest.split(" ", 1)[0]
            out.append(f"{indent}xor {reg}, {_key(width)}")
            out.append(f"{indent}mov {dest}, {reg}")
            out.append(f"{indent}xor {reg}, {_key(width)}")
            continue
        out.append(line)
    return "\n".join(out)


if __name__ == "__main__":
    # Slot loads gain a trailing decrypt; slot stores are wrapped; dynamic and fixed
    # slot offsets below the array end (incl. the rsp slot) are ciphered; the flags
    # word, the vstack and program memory are left alone.
    src = (
        "  mov rax, qword ptr [rsp+r8*8]\n"
        "  mov eax, dword ptr [rsp+r9*8]\n"
        "  mov qword ptr [rsp+r8*8], r10\n"
        "  mov qword ptr [rsp+rax*8], r10\n"  # renamed index register: still a slot
        "  mov rbx, qword ptr [rsp+rcx*8]\n"
        "  mov qword ptr [rsp + r9*8], rax\n"  # FP-handler spacing around + and *
        "  mov rax, qword ptr [rsp + r8 * 8]\n"
        "  mov cl, byte ptr [rsp+r8*8]\n"
        "  mov byte ptr [rsp+r8*8], cl\n"
        "  mov r9, qword ptr [rsp+56]\n"  # fixed data/rsp slot (< 0x80): ciphered
        "  mov qword ptr [rsp+56], r9\n"
        "  mov rax, qword ptr [rsp+128]\n"  # flags word (0x80): untouched
        "  mov qword ptr [rsp+r9+0x288], rax\n"  # vstack: untouched
        "  mov rax, qword ptr [r10]\n"  # program memory: untouched
    )
    got = cipher_register_slots(src)
    k, kd, kb = _key("qword"), _key("dword"), _key("byte")
    assert f"  mov rax, qword ptr [rsp+r8*8]\n  xor rax, {k}" in got
    assert f"  mov eax, dword ptr [rsp+r9*8]\n  xor eax, {kd}" in got
    assert f"  xor r10, {k}\n  mov qword ptr [rsp+r8*8], r10\n  xor r10, {k}" in got
    assert f"  xor r10, {k}\n  mov qword ptr [rsp+rax*8], r10\n  xor r10, {k}" in got
    assert f"  mov rbx, qword ptr [rsp+rcx*8]\n  xor rbx, {k}" in got
    assert f"  xor rax, {k}\n  mov qword ptr [rsp + r9*8], rax\n  xor rax, {k}" in got
    assert f"  mov rax, qword ptr [rsp + r8 * 8]\n  xor rax, {k}" in got
    assert f"  mov cl, byte ptr [rsp+r8*8]\n  xor cl, {kb}" in got
    assert f"  xor cl, {kb}\n  mov byte ptr [rsp+r8*8], cl\n  xor cl, {kb}" in got
    assert f"  mov r9, qword ptr [rsp+56]\n  xor r9, {k}" in got
    assert f"  xor r9, {k}\n  mov qword ptr [rsp+56], r9\n  xor r9, {k}" in got
    assert "[rsp+128]\n  xor" not in got  # flags word untouched
    assert "[rsp+r9+0x288], rax\n  xor" not in got  # vstack untouched
    assert got.count("[r10]\n  xor") == 0  # program memory untouched
    print("cipher_register_slots self-check passed")
