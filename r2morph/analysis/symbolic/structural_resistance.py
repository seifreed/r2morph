"""Static structural devirtualization-resistance signal.

The symbolic probe (:mod:`resistance_probe`) answers "can a bounded symbolic
adversary crack this function". Against a virtualized build it saturates at the
maximum (the adversary never terminates within budget), so it cannot rank one VM
build against a harder one. This module adds a complementary STATIC signal read
straight from the produced binary: the size and dispatch density of the injected
interpreter. It rises monotonically as more VM structure is added - more
handlers, micro-op expansion, shape polymorphism - so it scores incremental
hardening that the symbolic metric cannot distinguish.

Generic: everything is derived from the binary's own disassembly (radare2), with
no sample-specific constants.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)

# Weights combining the structural signals into one score. Register/memory-indirect
# dispatch is the virtualization hallmark (the interpreter's computed jump into the
# handler table, one per handler in a threaded design), so it dominates; raw size
# and branch fan-out contribute linearly. All three grow without bound, so the
# score never saturates the way the symbolic reach/no-reach signal does.
_WEIGHT_INSTRUCTIONS = 1.0
_WEIGHT_INDIRECT_DISPATCH = 10.0
_WEIGHT_BRANCH_TARGETS = 2.0

# radare2 op-type tags for a jump/call whose destination is a register or memory
# cell (an indirect transfer) - the dispatch shape a devirtualizer must resolve.
_INDIRECT_TRANSFER_TYPES = frozenset({"ujmp", "ucall", "rjmp", "rcall", "ijmp", "icall", "ucjmp"})

# Upper bound on bytes to linearly disassemble, so the probe stays bounded on a
# large real binary; the injected interpreters this measures are far smaller.
_MAX_DISASM_BYTES = 1 << 20


@dataclass(frozen=True)
class StructuralResistance:
    """Static structural-complexity signal for a binary's executable regions.

    ``structural_score`` is unbounded and monotonic in VM complexity; a binary
    carrying no interpreter scores near zero. ``expansion_ratio`` is the region's
    instruction count relative to a supplied native-run baseline (or to a single
    instruction when no baseline is given).
    """

    total_instructions: int
    indirect_jumps: int
    distinct_branch_targets: int
    expansion_ratio: float
    structural_score: float


class StructuralResistanceProbe:
    """Scores the structural complexity of the interpreter a binary carries."""

    def __init__(self, binary: Binary) -> None:
        self._binary = binary

    def measure(self, baseline_instructions: int | None = None) -> StructuralResistance:
        """Measure bounded disassembly across all executable segments.

        The virtualization pass may fragment its interpreter across adjacent
        executable segments. Function-boundary analysis stops at the first computed
        jump and misses threaded handlers, so bounded linear disassembly of every
        executable segment is the useful structural signal.
        """
        r2 = self._binary.r2
        if r2 is None:
            logger.info("Structural probe skipped: radare2 handle unavailable")
            return StructuralResistance(0, 0, 0, 0.0, 0.0)

        segments = r2.cmdj("iSSj") or []
        executable = [seg for seg in segments if "x" in seg.get("perm", "")]
        if not executable:
            return StructuralResistance(0, 0, 0, 0.0, 0.0)

        total = 0
        indirect = 0
        targets: set[int] = set()
        remaining = _MAX_DISASM_BYTES
        for segment in sorted(executable, key=lambda item: int(item.get("vaddr", 0))):
            if remaining <= 0 or "vaddr" not in segment:
                break
            size = min(int(segment.get("vsize", 0)), remaining)
            ops = r2.cmdj(f"pDj {size} @ {int(segment['vaddr'])}") or []
            for op in ops:
                if op.get("type") in (None, "invalid") or "disasm" not in op:
                    continue
                total += 1
                if op.get("type") in _INDIRECT_TRANSFER_TYPES:
                    indirect += 1
                target = op.get("jump")
                if target is not None:
                    targets.add(int(target))
            remaining -= size

        distinct_targets = len(targets)
        ratio = total / baseline_instructions if baseline_instructions else float(total)
        score = (
            _WEIGHT_INSTRUCTIONS * total
            + _WEIGHT_INDIRECT_DISPATCH * indirect
            + _WEIGHT_BRANCH_TARGETS * distinct_targets
        )
        logger.info(
            "Structural probe: instructions=%d indirect=%d targets=%d score=%.1f",
            total,
            indirect,
            distinct_targets,
            score,
        )
        return StructuralResistance(total, indirect, distinct_targets, ratio, score)
