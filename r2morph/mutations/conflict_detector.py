"""Mutation conflict detection and resolution."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.mutations.conflict_models import (
    Conflict,
    ConflictSeverity,
    ConflictType,
    MutationRegion,
    Resolution,
)
from r2morph.mutations.conflict_semantic import SemanticConflictDetector as _SemanticConflictDetector

logger = logging.getLogger(__name__)

SemanticConflictDetector = _SemanticConflictDetector


class RegionTracker:
    """
    Tracks mutation regions to detect conflicts.

    Maintains a registry of all applied mutations and their regions.
    """

    def __init__(self) -> None:
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

    def __init__(self) -> None:
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
