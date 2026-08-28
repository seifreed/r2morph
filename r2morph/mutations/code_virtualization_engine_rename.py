"""Per-handler scratch-register renaming for the engine VM.

Every handler body draws its temporaries from the same small pool in the same
order, so across builds - and across a single build's duplicated handler copies -
each body carries an identical register-allocation shape that one signature
recognizes everywhere. This applies a per-handler bijection over the scratch pool
``{rax, r8, r9, r10, r11}`` so two handlers computing the same thing spell it with
different registers, denying that fixed per-body fingerprint.

The rewrite is sound because those five are pure per-handler scratch: at the
dispatch each body is entered fresh (its operands re-read from the bytecode) and
left with only rsi/rsp/r13/r14/r15 and the frame live, so any consistent renaming
of the pool preserves the body's data flow. ``rcx`` is pinned (it carries the
shift count and the MBA temp), and every other register - rsi/rsp/r13/r14/r15,
the xmm file, and the junk-only rbx/rbp/r12 - is outside the pool and never
touched. A bijection also keeps each instruction's operand widths intact, so the
assembled body is the same length (the bytecode layout is unchanged).
"""

from __future__ import annotations

import re

import r2morph.core.randomness as random

# The five interchangeable scratch registers, each as its (q, d, w, b) spellings.
# rax keeps the legacy eax/ax/al names; r8-r11 use the d/w/b suffixes. rax has no
# usable high-byte peer (r8-r11 lack an ``h`` spelling), but the generated bodies
# never use ``ah``, so the pool needs no high-byte column.
_POOL: tuple[tuple[str, str, str, str], ...] = (
    ("rax", "eax", "ax", "al"),
    ("r8", "r8d", "r8w", "r8b"),
    ("r9", "r9d", "r9w", "r9b"),
    ("r10", "r10d", "r10w", "r10b"),
    ("r11", "r11d", "r11w", "r11b"),
)
_SPELLINGS: tuple[str, ...] = tuple(spelling for register in _POOL for spelling in register)
# Word-anchored so ``r10`` never matches inside ``r10d`` or a label like ``h_10``;
# longest-first keeps the alternation unambiguous even though the anchors suffice.
_TOKEN = re.compile(r"\b(" + "|".join(sorted(_SPELLINGS, key=len, reverse=True)) + r")\b")


# A body that pins a specific legacy register: ``lahf``/``sahf`` implicitly read or
# write ah, and a high-byte spelling (ah/bh/ch/dh) has no r8-r15 encoding at all.
# Renaming a pool register (rax) to r8-r15 in such a body both mis-encodes (a high
# byte cannot appear in a REX-prefixed instruction) and mis-targets the flags, so
# these bodies must be left unchanged - fails safe, exactly like _TRANSFER below.
_PINS_LEGACY_REGISTER = re.compile(r"\b(?:lahf|sahf|[abcd]h)\b")

# A body that pins rax/rdx by architecture: div/idiv read the dividend from and write
# the quotient/remainder to the fixed rdx:rax pair, cqo/cdq sign-extend rax into rdx,
# and cmpxchg implicitly compares against rax. rax is in the rename pool, so remapping
# it there would use the wrong architectural operand; these bodies must be left
# unchanged, exactly like the legacy-register pin above.
_PINS_FIXED_REGISTER = re.compile(r"\b(?:idiv|div|cqo|cdq|cmpxchg)\b")


def rename_body(body: str, rng: random.Random) -> str:
    """Rewrite the scratch registers in one handler body under a random bijection.

    ``rng`` seeds a permutation of the five-register pool; the result is the input
    with each scratch spelling mapped to its permuted register's spelling of the
    same width. ``rcx`` and every non-pool register are left untouched, so the
    body's meaning is preserved while its register fingerprint changes per handler.
    A body that pins a register - a legacy one (``lahf``/``sahf`` or a high-byte
    spelling) or the rax/rdx that ``div``/``idiv``/``cqo``/``cdq`` fix by architecture
    - is returned unchanged, since remapping rax there would miscompile.
    """
    if _PINS_LEGACY_REGISTER.search(body) or _PINS_FIXED_REGISTER.search(body):
        return body
    permutation = rng.sample(range(len(_POOL)), len(_POOL))
    mapping = {
        _POOL[source][width]: _POOL[target][width] for source, target in enumerate(permutation) for width in range(4)
    }
    return _TOKEN.sub(lambda match: mapping[match.group(0)], body)


# A control transfer inside a handler body. The engine's bodies are all pure-VM-
# internal, but the region VM has handlers that bridge to native code (a call's
# ``jmp r10`` after loading ABI argument registers, an exit's ``jmp 0xNNNN`` after
# restoring every GP register, a nested-layer transfer): there a pool register may
# hold a live program value, not dead scratch, so renaming it would miscompile.
_TRANSFER = re.compile(r"^\s*(jmp|call|syscall|ret)\b(.*)$", re.MULTILINE)


def rename_local_body(body: str, rng: random.Random) -> str:
    """Rename a handler body only if it never transfers control out of the VM.

    A body is safe to rename exactly when its every control transfer is the shared
    ``jmp vm_dispatch`` back-edge: then the scratch pool is pure per-handler dead
    scratch (:func:`rename_body`'s precondition). If the body bridges to native code
    or another layer - any ``jmp``/``call`` to a register, absolute address, or
    foreign label, or a ``syscall``/``ret`` - a pool register may carry a live
    program/ABI value there, so the body is returned unchanged. This fails safe: a
    misjudged body loses obfuscation, it never miscompiles.
    """
    for match in _TRANSFER.finditer(body):
        mnemonic, operand = match.group(1), match.group(2).strip()
        if mnemonic in ("syscall", "ret") or operand != "vm_dispatch":
            return body
    return rename_body(body, rng)
