"""
Pattern preservation for complex CFG handling.

This module provides infrastructure to preserve critical patterns
during mutations:
- Exception landing pads and handlers
- Jump tables and switch dispatchers
- PLT/GOT thunks
- Tail calls
- Virtual dispatch tables
"""

import logging
from typing import Any

from r2morph.analysis.pattern_preservation_detection import (
    detect_exception_patterns,
    detect_jump_table_patterns,
    detect_plt_got_patterns,
    detect_tail_call_patterns,
)
from r2morph.analysis.pattern_preservation_models import Criticality as _Criticality
from r2morph.analysis.pattern_preservation_models import ExclusionZone, PatternType, PreservedPattern
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)

Criticality = _Criticality


class PatternPreservationManager:
    """
    Manages preservation of critical binary patterns during mutations.

    Collects, indexes, and queries patterns that should be preserved
    or avoided during mutation operations.
    """

    def __init__(self, binary: Binary, default_radius: int = 8):
        self.binary = binary
        self.default_radius = default_radius
        self._patterns: list[PreservedPattern] = []
        self._exclusion_zones: list[ExclusionZone] = []
        self._address_index: dict[int, list[PreservedPattern]] = {}
        self._exception_reader: Any | None = None
        self._switch_analyzer: Any | None = None
        self._analyzed = False

    def analyze(self) -> dict[str, Any]:
        """
        Analyze binary to detect all preservation patterns.

        Returns:
            Summary of detected patterns
        """
        if self._analyzed:
            return self._get_summary()

        self._detect_exception_patterns()
        self._detect_jump_table_patterns()
        self._detect_plt_got_patterns()
        self._detect_tail_call_patterns()
        self._build_exclusion_zones()
        self._build_address_index()
        self._analyzed = True

        return self._get_summary()

    def _detect_exception_patterns(self) -> None:
        """Detect exception handling patterns (landing pads, handlers)."""
        detect_exception_patterns(self)

    def _detect_jump_table_patterns(self) -> None:
        """Detect jump tables and switch dispatch patterns."""
        detect_jump_table_patterns(self)

    def _detect_plt_got_patterns(self) -> None:
        """Detect PLT thunks and GOT entries."""
        detect_plt_got_patterns(self)

    def _detect_tail_call_patterns(self) -> None:
        """Detect tail call patterns."""
        detect_tail_call_patterns(self)

    def _build_exclusion_zones(self) -> None:
        """Build exclusion zones from patterns."""
        self._exclusion_zones = []

        for pattern in self._patterns:
            radius = self._get_radius_for_pattern(pattern)
            zone = ExclusionZone(
                start_address=pattern.start_address,
                end_address=pattern.end_address,
                pattern_type=pattern.type,
                reason=f"Preserving {pattern.type.value}",
                radius=radius,
            )
            self._exclusion_zones.append(zone)

    def _get_radius_for_pattern(self, pattern: PreservedPattern) -> int:
        """Get exclusion radius based on pattern type."""
        radii = {
            PatternType.EXCEPTION_HANDLER: 16,
            PatternType.LANDING_PAD: 8,
            PatternType.JUMP_TABLE: 16,
            PatternType.JUMP_TABLE_ENTRY: 4,
            PatternType.SWITCH_DISPATCHER: 16,
            PatternType.VIRTUAL_DISPATCHER: 32,
            PatternType.PLT_THUNK: 16,
            PatternType.GOT_ENTRY: 8,
            PatternType.TAIL_CALL: 4,
            PatternType.INDIRECT_JUMP: 8,
        }
        return radii.get(pattern.type, self.default_radius)

    def _build_address_index(self) -> None:
        """Build address index for fast lookup."""
        self._address_index = {}

        for pattern in self._patterns:
            for addr in range(pattern.start_address, pattern.end_address):
                if addr not in self._address_index:
                    self._address_index[addr] = []
                self._address_index[addr].append(pattern)

    def _get_summary(self) -> dict[str, Any]:
        """Get summary of detected patterns."""
        counts: dict[str, int] = {}
        for pattern in self._patterns:
            key = pattern.type.value
            counts[key] = counts.get(key, 0) + 1

        return {
            "total_patterns": len(self._patterns),
            "total_exclusion_zones": len(self._exclusion_zones),
            "pattern_counts": counts,
            "patterns": [p.to_dict() for p in self._patterns],
        }

    def should_preserve(self, address: int) -> bool:
        """
        Check if an address should be preserved.

        Args:
            address: Address to check

        Returns:
            True if address must be preserved
        """
        for zone in self._exclusion_zones:
            if zone.contains(address):
                return zone.pattern_type in (
                    PatternType.EXCEPTION_HANDLER,
                    PatternType.LANDING_PAD,
                    PatternType.JUMP_TABLE,
                    PatternType.PLT_THUNK,
                    PatternType.GOT_ENTRY,
                )
        return False

    def should_avoid(self, address: int) -> bool:
        """
        Check if an address should be avoided during mutation.

        Args:
            address: Address to check

        Returns:
            True if address should be avoided
        """
        for zone in self._exclusion_zones:
            if zone.contains(address):
                return True
        return False

    def get_pattern_at(self, address: int) -> PreservedPattern | None:
        """
        Get pattern at a specific address.

        Args:
            address: Address to query

        Returns:
            PreservedPattern if found, None otherwise
        """
        patterns = self._address_index.get(address, [])
        return patterns[0] if patterns else None

    def get_patterns_in_range(self, start: int, end: int) -> list[PreservedPattern]:
        """
        Get all patterns in an address range.

        Args:
            start: Start address
            end: End address

        Returns:
            List of PreservedPattern instances
        """
        result = []
        seen = set()

        for addr in range(start, end):
            for pattern in self._address_index.get(addr, []):
                if id(pattern) not in seen:
                    seen.add(id(pattern))
                    result.append(pattern)

        return result

    def get_exclusion_zones(self) -> list[ExclusionZone]:
        """
        Get all exclusion zones.

        Returns:
            List of ExclusionZone instances
        """
        return self._exclusion_zones

    def get_exclusion_zones_for_type(self, pattern_type: PatternType) -> list[ExclusionZone]:
        """
        Get exclusion zones for a specific pattern type.

        Args:
            pattern_type: Type of pattern

        Returns:
            List of ExclusionZone instances
        """
        return [z for z in self._exclusion_zones if z.pattern_type == pattern_type]

    def get_safe_addresses(
        self,
        start: int,
        end: int,
        min_gap: int = 1,
    ) -> list[tuple[int, int]]:
        """
        Get safe address ranges within a region.

        Args:
            start: Start address
            end: End address
            min_gap: Minimum gap between safe regions

        Returns:
            List of (start, end) tuples for safe regions
        """
        safe_regions = []
        current_start = None

        for addr in range(start, end):
            if not self.should_avoid(addr):
                if current_start is None:
                    current_start = addr
            else:
                if current_start is not None:
                    if addr - current_start >= min_gap:
                        safe_regions.append((current_start, addr))
                    current_start = None

        if current_start is not None and end - current_start >= min_gap:
            safe_regions.append((current_start, end))

        return safe_regions

    def get_patterns_by_type(self, pattern_type: PatternType) -> list[PreservedPattern]:
        """
        Get all patterns of a specific type.

        Args:
            pattern_type: Type of pattern

        Returns:
            List of PreservedPattern instances
        """
        return [p for p in self._patterns if p.type == pattern_type]

    def report(self) -> dict[str, Any]:
        """
        Generate a detailed preservation report.

        Returns:
            Dictionary with full preservation analysis
        """
        return {
            "summary": self._get_summary(),
            "exclusion_zones": [z.to_dict() for z in self._exclusion_zones],
            "total_excluded_bytes": sum(z.expanded_end - z.expanded_start for z in self._exclusion_zones),
        }
