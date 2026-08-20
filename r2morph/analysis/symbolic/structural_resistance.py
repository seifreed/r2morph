"""Static structural devirtualization-resistance signal.

The symbolic probe (:mod:`resistance_probe`) answers "can a bounded symbolic
adversary crack this function". Against a virtualized build it saturates at the
maximum (the adversary never terminates within budget), so it cannot rank one VM
build against a harder one. This module adds a complementary STATIC signal read
straight from the produced binary: dispatch features of the injected interpreter.
Raw instruction count is reported separately as expansion evidence but does not
inflate the resistance score, so code bloat alone cannot masquerade as harder
analysis.

Generic: everything is derived from the binary's own disassembly (radare2), with
no sample-specific constants.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)

# Weights combining dispatch signals into one score. Register/memory-indirect
# dispatch is the virtualization hallmark; branch-target diversity is supporting
# evidence. Instruction count remains a separate expansion measurement.
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
        score = _dispatch_score(indirect, distinct_targets)
        logger.info(
            "Structural probe: instructions=%d indirect=%d targets=%d score=%.1f",
            total,
            indirect,
            distinct_targets,
            score,
        )
        return StructuralResistance(total, indirect, distinct_targets, ratio, score)


def _dispatch_score(indirect_jumps: int, distinct_branch_targets: int) -> float:
    """Score dispatch structure without rewarding raw instruction bloat."""
    return _WEIGHT_INDIRECT_DISPATCH * indirect_jumps + _WEIGHT_BRANCH_TARGETS * distinct_branch_targets
