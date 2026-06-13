"""Semantic conflict analysis for mutation interactions."""

from __future__ import annotations

from typing import Any


class SemanticConflictDetector:
    """
    Detects semantic conflicts between mutations.

    Semantic conflicts occur when:
    1. Mutations individually preserve semantics but combined may not
    2. Mutations alter invariants that other mutations depend on
    3. Mutations change program behavior in ways that interact unexpectedly
    """

    INVARIANT_PATTERNS = {
        "x86": {
            "calling_convention": ["eax", "ecx", "edx"],
            "callee_saved": ["ebx", "esi", "edi", "ebp", "esp"],
            "stack_pointer": ["esp"],
            "frame_pointer": ["ebp"],
        },
        "arm": {
            "calling_convention": ["r0", "r1", "r2", "r3"],
            "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
            "stack_pointer": ["sp"],
            "frame_pointer": ["fp", "r7"],
        },
        "arm64": {
            "calling_convention": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            "callee_saved": ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29"],
            "stack_pointer": ["sp"],
            "frame_pointer": ["x29", "fp"],
        },
    }

    def __init__(self, arch: str = "x86"):
        """
        Initialize semantic conflict detector.

        Args:
            arch: Architecture for ABI-aware analysis
        """
        self.arch = arch
        self._invariant_patterns = self.INVARIANT_PATTERNS.get(arch, self.INVARIANT_PATTERNS["x86"])
        self._tracked_invariants: dict[int, list[dict[str, Any]]] = {}

    def analyze_register_conflicts(
        self,
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Analyze mutations for register-based semantic conflicts.

        Args:
            mutations: List of mutation dictionaries

        Returns:
            List of potential semantic conflicts
        """
        conflicts = []
        register_uses: dict[str, list[int]] = {}

        for i, mutation in enumerate(mutations):
            regs = mutation.get("affected_registers", set())
            if isinstance(regs, list):
                regs = set(regs)

            for reg in regs:
                if reg not in register_uses:
                    register_uses[reg] = []
                register_uses[reg].append(i)

        for reg, indices in register_uses.items():
            if len(indices) > 1:
                caller_saved = set(self._invariant_patterns.get("calling_convention", []))
                callee_saved = set(self._invariant_patterns.get("callee_saved", []))

                if reg in caller_saved:
                    continue

                if reg in callee_saved or reg in self._invariant_patterns.get("stack_pointer", []):
                    conflicts.append(
                        {
                            "type": "semantic_register_violation",
                            "severity": "critical",
                            "register": reg,
                            "mutation_indices": indices,
                            "description": f"Callee-saved register {reg} modified by multiple mutations",
                            "resolution": "Ensure proper save/restore or use different registers",
                        }
                    )

        return conflicts

    def analyze_control_flow_conflicts(
        self,
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Analyze mutations for control flow semantic conflicts.

        Args:
            mutations: List of mutation dictionaries

        Returns:
            List of control flow semantic conflicts
        """
        conflicts = []
        cf_mutations = []

        for i, mutation in enumerate(mutations):
            if mutation.get("control_flow_changed", False):
                cf_mutations.append((i, mutation))

        if len(cf_mutations) > 1:
            for i, (idx1, m1) in enumerate(cf_mutations):
                for idx2, m2 in cf_mutations[i + 1 :]:
                    m1.get("start", m1.get("address", 0))
                    m2.get("start", m2.get("address", 0))

                    conflicts.append(
                        {
                            "type": "semantic_control_flow",
                            "severity": "high",
                            "mutation_indices": [idx1, idx2],
                            "description": "Multiple control flow mutations may interact unexpectedly",
                            "resolution": "Apply control flow mutations in separate passes or verify combined semantics",
                        }
                    )

        return conflicts

    def analyze_stack_conflicts(
        self,
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Analyze mutations for stack-related semantic conflicts.

        Args:
            mutations: List of mutation dictionaries

        Returns:
            List of stack semantic conflicts
        """
        conflicts = []
        stack_regs = set(self._invariant_patterns.get("stack_pointer", []))

        stack_mods = []
        for i, mutation in enumerate(mutations):
            regs = mutation.get("affected_registers", set())
            if isinstance(regs, list):
                regs = set(regs)

            if regs & stack_regs:
                stack_mods.append((i, mutation))

        if len(stack_mods) > 1:
            conflicts.append(
                {
                    "type": "semantic_stack_modification",
                    "severity": "critical",
                    "mutation_indices": [idx for idx, _ in stack_mods],
                    "description": "Multiple mutations modify stack state",
                    "resolution": "Ensure consistent stack discipline across all mutations",
                }
            )

        return conflicts

    def analyze_data_flow_conflicts(
        self,
        mutations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Analyze mutations for data flow semantic conflicts.

        Checks if mutations that read/write overlapping memory regions
        may have ordering dependencies that affect semantics.

        Args:
            mutations: List of mutation dictionaries

        Returns:
            List of data flow semantic conflicts
        """
        conflicts = []
        mem_regions: list[tuple[int, int, int, dict[str, Any]]] = []

        for i, mutation in enumerate(mutations):
            start = mutation.get("start", mutation.get("address", 0))
            size = mutation.get("size", mutation.get("length", 4))
            end = start + size

            writes = mutation.get("writes_memory", [])
            reads = mutation.get("reads_memory", [])

            mem_regions.append(
                (
                    start,
                    end,
                    i,
                    {
                        "writes": writes if isinstance(writes, list) else [],
                        "reads": reads if isinstance(reads, list) else [],
                    },
                )
            )

        for i, (start1, end1, idx1, meta1) in enumerate(mem_regions):
            for start2, end2, idx2, meta2 in mem_regions[i + 1 :]:
                if start1 < end2 and start2 < end1:
                    write1 = set(meta1.get("writes", []))
                    write2 = set(meta2.get("writes", []))
                    read1 = set(meta1.get("reads", []))
                    read2 = set(meta2.get("reads", []))

                    if write1 & write2:
                        conflicts.append(
                            {
                                "type": "semantic_write_write",
                                "severity": "high",
                                "mutation_indices": [idx1, idx2],
                                "description": "Both mutations write to overlapping memory regions",
                                "resolution": "Order mutations carefully or use different regions",
                            }
                        )
                    elif write1 & read2:
                        conflicts.append(
                            {
                                "type": "semantic_write_read",
                                "severity": "medium",
                                "mutation_indices": [idx1, idx2],
                                "description": "First mutation writes to regions read by second mutation",
                                "resolution": f"Ensure mutation {idx1} is applied before mutation {idx2}",
                                "ordering": [idx1, idx2],
                            }
                        )
                    elif read1 & write2:
                        conflicts.append(
                            {
                                "type": "semantic_read_write",
                                "severity": "medium",
                                "mutation_indices": [idx1, idx2],
                                "description": "First mutation reads from regions written by second mutation",
                                "resolution": f"Ensure mutation {idx2} is applied after mutation {idx1}",
                                "ordering": [idx2, idx1],
                            }
                        )

        return conflicts

    def detect_semantic_conflicts(
        self,
        mutations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Detect all semantic conflicts between mutations.

        Args:
            mutations: List of mutation dictionaries

        Returns:
            Dictionary with all detected semantic conflicts
        """
        all_conflicts = []

        all_conflicts.extend(self.analyze_register_conflicts(mutations))
        all_conflicts.extend(self.analyze_control_flow_conflicts(mutations))
        all_conflicts.extend(self.analyze_stack_conflicts(mutations))
        all_conflicts.extend(self.analyze_data_flow_conflicts(mutations))

        severity_counts: dict[str, int] = {}
        for conflict in all_conflicts:
            sev = conflict.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_conflicts": len(all_conflicts),
            "severity_counts": severity_counts,
            "conflicts": all_conflicts,
            "has_critical": severity_counts.get("critical", 0) > 0,
            "has_high": severity_counts.get("high", 0) > 0,
        }


__all__ = ["SemanticConflictDetector"]
