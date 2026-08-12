"""Post-process VM handler assembly to encrypt its GP register file.

The region VM keeps the program's 16 GP registers in a flat frame array at
``[rsp + slot*8]`` (the relocated program rsp included, at ``[rsp + rsp_off]``).
Stored in the clear, a decompiler reads that array as a plain register context.

This module ciphers it in one place instead of at every handler site: it rewrites
each register-slot ``mov`` in generated handler assembly to XOR the value with
the self-checksum key broadcast materialized at entry - decrypt right after every
slot load, encrypt right before every slot store. Because the key byte is uniform across all eight lanes,
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


def _key(width: str, key_qword_offset: int) -> str:
    return f"{width} ptr [rsp+{key_qword_offset}]"


def _is_slot(disp: str) -> bool:
    """A scaled index is always a slot; a fixed decimal is one only below the array end."""
    return "*" in disp or int(disp) < _GP_ARRAY_END


def cipher_register_slots(asm: str, key_qword_offset: int = _KEY_QWORD_SLOT) -> str:
    """Return ``asm`` with every GP register-slot load decrypted and store encrypted."""
    out: list[str] = []
    for line in asm.split("\n"):
        read = _READ_RE.match(line)
        if read and _is_slot(read.group(4)):
            indent, reg, width, _ = read.groups()
            out.append(line)
            out.append(f"{indent}xor {reg}, {_key(width, key_qword_offset)}")
            continue
        write = _WRITE_RE.match(line)
        if write and _is_slot(write.group(3)):
            indent, dest, _, reg = write.groups()
            width = dest.split(" ", 1)[0]
            out.append(f"{indent}xor {reg}, {_key(width, key_qword_offset)}")
            out.append(f"{indent}mov {dest}, {reg}")
            out.append(f"{indent}xor {reg}, {_key(width, key_qword_offset)}")
            continue
        out.append(line)
    return "\n".join(out)
