"""
Mutation conflict detection and resolution.

Detects and prevents conflicting mutations from being applied
in the same region.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# Map sub-registers to their 64-bit base register for conflict detection
_REG_TO_BASE: dict[str, str] = {}
for _base, _variants in {
    "rax": ("eax", "ax", "al", "ah"),
    "rbx": ("ebx", "bx", "bl", "bh"),
    "rcx": ("ecx", "cx", "cl", "ch"),
    "rdx": ("edx", "dx", "dl", "dh"),
    "rsi": ("esi", "si", "sil"),
    "rdi": ("edi", "di", "dil"),
    "rbp": ("ebp", "bp", "bpl"),
    "rsp": ("esp", "sp", "spl"),
    "r8": ("r8d", "r8w", "r8b"),
    "r9": ("r9d", "r9w", "r9b"),
    "r10": ("r10d", "r10w", "r10b"),
    "r11": ("r11d", "r11w", "r11b"),
    "r12": ("r12d", "r12w", "r12b"),
    "r13": ("r13d", "r13w", "r13b"),
    "r14": ("r14d", "r14w", "r14b"),
    "r15": ("r15d", "r15w", "r15b"),
}.items():
    _REG_TO_BASE[_base] = _base
    for _v in _variants:
        _REG_TO_BASE[_v] = _base


def _normalize_registers(regs: set[str]) -> set[str]:
    """Normalize register names to their 64-bit base for conflict comparison."""
    return {_REG_TO_BASE.get(r.lower(), r.lower()) for r in regs}


class ConflictType(Enum):
    """Types of mutation conflicts."""

    OVERLAP = "overlap"
    REGISTER_INTERFERENCE = "register_interference"
    MEMORY_INTERFERENCE = "memory_interference"
    CONTROL_FLOW = "control_flow"
    DEPENDENCY = "dependency"
    SEMANTIC = "semantic"


class ConflictSeverity(Enum):
    """Severity of a conflict."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MutationRegion:
    """Represents a region affected by a mutation."""

    start: int
    end: int
    pass_name: str = ""
    affected_registers: set[str] = field(default_factory=set)
    affected_memory: set[int] = field(default_factory=set)
    control_flow_changed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.start, self.end, self.pass_name))

    def overlaps(self, other: "MutationRegion") -> bool:
        """Check if this region overlaps with another."""
        return self.start < other.end and other.start < self.end

    def conflicts_with(self, other: "MutationRegion") -> ConflictType | None:
        """
        Determine conflict type with another region.

        Args:
            other: Other mutation region

        Returns:
            ConflictType or None if no conflict
        """
        if self.overlaps(other):
            return ConflictType.OVERLAP

        if _normalize_registers(self.affected_registers) & _normalize_registers(other.affected_registers):
            return ConflictType.REGISTER_INTERFERENCE

        if self.affected_memory & other.affected_memory:
            return ConflictType.MEMORY_INTERFERENCE

        if self.control_flow_changed and other.control_flow_changed:
            return ConflictType.CONTROL_FLOW

        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "start": f"0x{self.start:x}",
            "end": f"0x{self.end:x}",
            "pass_name": self.pass_name,
            "affected_registers": sorted(self.affected_registers),
            "affected_memory": sorted(f"0x{a:x}" for a in self.affected_memory),
            "control_flow_changed": self.control_flow_changed,
        }


@dataclass
class Conflict:
    """Represents a conflict between two mutations."""

    conflict_id: int
    conflict_type: ConflictType
    severity: ConflictSeverity
    region1: MutationRegion
    region2: MutationRegion
    description: str = ""
    resolution_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "conflict_id": self.conflict_id,
            "type": self.conflict_type.value,
            "severity": self.severity.value,
            "region1": self.region1.to_dict(),
            "region2": self.region2.to_dict(),
            "description": self.description,
            "resolution_hint": self.resolution_hint,
        }


@dataclass
class Resolution:
    """Represents a resolution for a conflict."""

    conflict: Conflict
    strategy: str
    description: str = ""
    action: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "conflict_id": self.conflict.conflict_id,
            "strategy": self.strategy,
            "description": self.description,
            "action": self.action,
        }


class RegionTracker:
    """
    Tracks mutation regions to detect conflicts.

    Maintains a registry of all applied mutations and their regions.
    """

    def __init__(self):
        self._regions: dict[int, MutationRegion] = {}
        self._regions_by_address: dict[int, list[int]] = {}
        self._region_counter = 0

    def track_mutation(
        self,
        start: int,
        end: int,
        pass_name: str,
        affected_registers: set[str] | None = None,
        affected_memory: set[int] | None = None,
        control_flow_changed: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """
        Track a mutation region.

        Args:
            start: Start address
            end: End address
            pass_name: Mutation pass name
            affected_registers: Set of affected registers
            affected_memory: Set of affected memory addresses
            control_flow_changed: Whether control flow was modified
            metadata: Additional metadata

        Returns:
            Region ID
        """
        region_id = self._region_counter
        self._region_counter += 1

        region = MutationRegion(
            start=start,
            end=end,
            pass_name=pass_name,
            affected_registers=affected_registers or set(),
            affected_memory=affected_memory or set(),
            control_flow_changed=control_flow_changed,
            metadata=metadata or {},
        )

        self._regions[region_id] = region

        for addr in range(start, end):
            if addr not in self._regions_by_address:
                self._regions_by_address[addr] = []
            self._regions_by_address[addr].append(region_id)

        return region_id

    def get_regions_at(self, addr: int) -> list[MutationRegion]:
        """
        Get all regions that affect an address.

        Args:
            addr: Address to check

        Returns:
            List of mutation regions
        """
        region_ids = self._regions_by_address.get(addr, [])
        return [self._regions[rid] for rid in region_ids if rid in self._regions]

    def get_overlaps(self) -> list[tuple[MutationRegion, MutationRegion]]:
        """
        Find all overlapping regions.

        Returns:
            List of overlapping region pairs
        """
        overlaps = []
        region_ids = list(self._regions.keys())

        for i, rid1 in enumerate(region_ids):
            for rid2 in region_ids[i + 1 :]:
                region1 = self._regions[rid1]
                region2 = self._regions[rid2]

                if region1.overlaps(region2):
                    overlaps.append((region1, region2))

        return overlaps

    def get_region_count(self) -> int:
        """Get total number of tracked regions."""
        return len(self._regions)

    def clear(self) -> None:
        """Clear all tracked regions."""
        self._regions.clear()
        self._regions_by_address.clear()
        self._region_counter = 0


class ConflictDetector:
    """
    Detects conflicts between mutations.

    Analyzes mutation regions for overlaps, register conflicts,
    memory conflicts, and control flow conflicts.
    """

    def __init__(self):
        self._conflict_counter = 0
        self._region_tracker = RegionTracker()

    def detect_overlaps(self, regions: list[MutationRegion]) -> list[Conflict]:
        """
        Detect overlapping mutation regions.

        Args:
            regions: List of mutation regions

        Returns:
            List of overlap conflicts
        """
        conflicts = []

        for i, region1 in enumerate(regions):
            for region2 in regions[i + 1 :]:
                if region1.overlaps(region2):
                    conflict = Conflict(
                        conflict_id=self._conflict_counter,
                        conflict_type=ConflictType.OVERLAP,
                        severity=ConflictSeverity.HIGH,
                        region1=region1,
                        region2=region2,
                        description=f"Regions overlap: 0x{region1.start:x}-0x{region1.end:x} and 0x{region2.start:x}-0x{region2.end:x}",
                        resolution_hint="Consider reordering mutations or using different addresses",
                    )
                    conflicts.append(conflict)
                    self._conflict_counter += 1

        return conflicts

    def find_interferences(
        self,
        regions: list[MutationRegion],
    ) -> list[Conflict]:
        """
        Find register and memory interferences between regions.

        Args:
            regions: List of mutation regions

        Returns:
            List of interference conflicts
        """
        conflicts = []

        for i, region1 in enumerate(regions):
            for region2 in regions[i + 1 :]:
                conflict_type = region1.conflicts_with(region2)

                if conflict_type:
                    severity = self._determine_severity(conflict_type)

                    conflict = Conflict(
                        conflict_id=self._conflict_counter,
                        conflict_type=conflict_type,
                        severity=severity,
                        region1=region1,
                        region2=region2,
                        description=self._describe_conflict(conflict_type, region1, region2),
                        resolution_hint=self._hint_for_conflict(conflict_type),
                    )
                    conflicts.append(conflict)
                    self._conflict_counter += 1

        return conflicts

    def _determine_severity(self, conflict_type: ConflictType) -> ConflictSeverity:
        """Determine severity for a conflict type."""
        severity_map = {
            ConflictType.OVERLAP: ConflictSeverity.HIGH,
            ConflictType.REGISTER_INTERFERENCE: ConflictSeverity.MEDIUM,
            ConflictType.MEMORY_INTERFERENCE: ConflictSeverity.MEDIUM,
            ConflictType.CONTROL_FLOW: ConflictSeverity.CRITICAL,
            ConflictType.DEPENDENCY: ConflictSeverity.LOW,
            ConflictType.SEMANTIC: ConflictSeverity.HIGH,
        }
        return severity_map.get(conflict_type, ConflictSeverity.MEDIUM)

    def _describe_conflict(
        self,
        conflict_type: ConflictType,
        region1: MutationRegion,
        region2: MutationRegion,
    ) -> str:
        """Generate description for a conflict."""
        if conflict_type == ConflictType.REGISTER_INTERFERENCE:
            common = region1.affected_registers & region2.affected_registers
            return f"Register interference: both mutations affect {', '.join(common)}"
        elif conflict_type == ConflictType.MEMORY_INTERFERENCE:
            return f"Memory interference between {region1.pass_name} and {region2.pass_name}"
        elif conflict_type == ConflictType.CONTROL_FLOW:
            return "Multiple mutations modify control flow in nearby regions"
        return f"{conflict_type.value} conflict detected"

    def _hint_for_conflict(self, conflict_type: ConflictType) -> str:
        """Get resolution hint for a conflict type."""
        hints = {
            ConflictType.OVERLAP: "Split mutations or use separate regions",
            ConflictType.REGISTER_INTERFERENCE: "Ensure mutations use different registers or apply sequentially",
            ConflictType.MEMORY_INTERFERENCE: "Use different memory regions or apply in sequence",
            ConflictType.CONTROL_FLOW: "Only one control-flow mutation per region",
            ConflictType.DEPENDENCY: "Check mutation dependencies",
            ConflictType.SEMANTIC: "Verify semantic equivalence",
        }
        return hints.get(conflict_type, "Review mutation overlap")

    def validate_pipeline(
        self,
        passes: list[tuple[str, MutationRegion]],
    ) -> list[Conflict]:
        """
        Validate a pipeline of mutation passes.

        Args:
            passes: List of (pass_name, region) tuples

        Returns:
            List of conflicts found
        """
        all_conflicts: list[Conflict] = []
        regions = [region for _, region in passes]

        overlap_conflicts = self.detect_overlaps(regions)
        all_conflicts.extend(overlap_conflicts)

        interference_conflicts = self.find_interferences(regions)
        all_conflicts.extend(interference_conflicts)

        return all_conflicts

    def suggest_resolutions(
        self,
        conflicts: list[Conflict],
    ) -> list[Resolution]:
        """
        Suggest resolutions for conflicts.

        Args:
            conflicts: List of conflicts

        Returns:
            List of resolutions
        """
        resolutions = []

        for conflict in conflicts:
            if conflict.conflict_type == ConflictType.OVERLAP:
                resolution = Resolution(
                    conflict=conflict,
                    strategy="reorder",
                    description="Apply mutations in sequence, checking for overlap",
                    action="apply_sequential",
                )

            elif conflict.conflict_type == ConflictType.REGISTER_INTERFERENCE:
                resolution = Resolution(
                    conflict=conflict,
                    strategy="skip",
                    description="Skip second mutation to avoid register conflict",
                    action="skip_second",
                )

            elif conflict.conflict_type == ConflictType.CONTROL_FLOW:
                resolution = Resolution(
                    conflict=conflict,
                    strategy="abort",
                    description="Multiple control flow modifications detected",
                    action="abort_pipeline",
                )

            else:
                resolution = Resolution(
                    conflict=conflict,
                    strategy="merge",
                    description="Consider merging mutations",
                    action="merge_mutations",
                )

            resolutions.append(resolution)

        return resolutions

    def get_region_tracker(self) -> RegionTracker:
        """Get the region tracker instance."""
        return self._region_tracker


def analyze_mutations_for_conflicts(
    mutations: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Convenience function to analyze mutations for conflicts.

    Args:
        mutations: List of mutation dictionaries with 'start', 'end', 'pass_name'

    Returns:
        Dictionary with analysis results
    """
    detector = ConflictDetector()
    regions: list[MutationRegion] = []

    for mutation in mutations:
        start = mutation.get("start", mutation.get("address", 0))
        size = mutation.get("size", mutation.get("length", 4))
        end = start + size

        region = MutationRegion(
            start=start,
            end=end,
            pass_name=mutation.get("pass_name", "unknown"),
            affected_registers=set(mutation.get("registers", [])),
            affected_memory=set(mutation.get("memory", [])),
            control_flow_changed=mutation.get("control_flow", False),
        )
        regions.append(region)

    conflicts = detector.validate_pipeline([(r.pass_name, r) for r in regions])
    resolutions = detector.suggest_resolutions(conflicts)

    return {
        "total_mutations": len(mutations),
        "total_regions": len(regions),
        "conflicts_found": len(conflicts),
        "conflicts": [c.to_dict() for c in conflicts],
        "resolutions": [r.to_dict() for r in resolutions],
        "has_critical": any(c.severity == ConflictSeverity.CRITICAL for c in conflicts),
        "has_high": any(c.severity == ConflictSeverity.HIGH for c in conflicts),
    }


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
                    start1 = m1.get("start", m1.get("address", 0))
                    start2 = m2.get("start", m2.get("address", 0))

                    conflicts.append(
                        {
                            "type": "semantic_control_flow",
                            "severity": "high",
                            "mutation_indices": [idx1, idx2],
                            "description": f"Multiple control flow mutations may interact unexpectedly",
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
