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

import random
import re

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


def rename_body(body: str, rng: random.Random) -> str:
    """Rewrite the scratch registers in one handler body under a random bijection.

    ``rng`` seeds a permutation of the five-register pool; the result is the input
    with each scratch spelling mapped to its permuted register's spelling of the
    same width. ``rcx`` and every non-pool register are left untouched, so the
    body's meaning is preserved while its register fingerprint changes per handler.
    """
    permutation = rng.sample(range(len(_POOL)), len(_POOL))
    mapping = {
        _POOL[source][width]: _POOL[target][width] for source, target in enumerate(permutation) for width in range(4)
    }
    return _TOKEN.sub(lambda match: mapping[match.group(0)], body)
