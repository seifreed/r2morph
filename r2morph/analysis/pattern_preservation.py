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
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.core.binary import Binary
from r2morph.analysis.exception import ExceptionInfoReader
from r2morph.analysis.switch_table import SwitchTableAnalyzer

logger = logging.getLogger(__name__)


class PatternType(Enum):
    EXCEPTION_HANDLER = "exception_handler"
    LANDING_PAD = "landing_pad"
    JUMP_TABLE = "jump_table"
    JUMP_TABLE_ENTRY = "jump_table_entry"
    SWITCH_DISPATCHER = "switch_dispatcher"
    VIRTUAL_DISPATCHER = "virtual_dispatcher"
    PLT_THUNK = "plt_thunk"
    GOT_ENTRY = "got_entry"
    TAIL_CALL = "tail_call"
    INDIRECT_JUMP = "indirect_jump"


class Criticality(Enum):
    PRESERVE = "preserve"
    AVOID = "avoid"
    CAUTION = "caution"


@dataclass
class PreservedPattern:
    type: PatternType
    start_address: int
    end_address: int
    criticality: Criticality = Criticality.PRESERVE
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return self.end_address - self.start_address

    def contains(self, address: int) -> bool:
        return self.start_address <= address < self.end_address

    def overlaps(self, start: int, end: int) -> bool:
        return self.start_address < end and start < self.end_address

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "start_address": f"0x{self.start_address:x}",
            "end_address": f"0x{self.end_address:x}",
            "size": self.size,
            "criticality": self.criticality.value,
            "source": self.source,
        }


@dataclass
class ExclusionZone:
    start_address: int
    end_address: int
    pattern_type: PatternType
    reason: str = ""
    radius: int = 0

    @property
    def expanded_start(self) -> int:
        return max(0, self.start_address - self.radius)

    @property
    def expanded_end(self) -> int:
        return self.end_address + self.radius

    def contains(self, address: int) -> bool:
        return self.expanded_start <= address < self.expanded_end

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_address": f"0x{self.expanded_start:x}",
            "end_address": f"0x{self.expanded_end:x}",
            "pattern_type": self.pattern_type.value,
            "reason": self.reason,
            "radius": self.radius,
        }


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
        self._exception_reader: ExceptionInfoReader | None = None
        self._switch_analyzer: SwitchTableAnalyzer | None = None
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
        try:
            self._exception_reader = ExceptionInfoReader(self.binary)
            frames = self._exception_reader.read_exception_frames()

            for func_addr, frame in frames.items():
                if frame.landing_pads:
                    pattern = PreservedPattern(
                        type=PatternType.EXCEPTION_HANDLER,
                        start_address=frame.function_start,
                        end_address=frame.function_end,
                        criticality=Criticality.PRESERVE,
                        source="exception_analysis",
                        metadata={"function_address": func_addr},
                    )
                    self._patterns.append(pattern)

                    for pad in frame.landing_pads:
                        landing_pattern = PreservedPattern(
                            type=PatternType.LANDING_PAD,
                            start_address=pad.address,
                            end_address=pad.address + max(pad.size, 16),
                            criticality=Criticality.PRESERVE,
                            source="exception_analysis",
                            metadata={"action": pad.action.value},
                        )
                        self._patterns.append(landing_pattern)

        except Exception as e:
            logger.debug(f"Exception pattern detection failed: {e}")

    def _detect_jump_table_patterns(self) -> None:
        """Detect jump tables and switch dispatch patterns."""
        try:
            self._switch_analyzer = SwitchTableAnalyzer(self.binary)
            functions = self.binary.get_functions()

            for func in functions:
                func_addr = func.get("offset", func.get("addr", 0))
                if func_addr == 0:
                    continue

                try:
                    jump_tables, other_jumps = self._switch_analyzer.detect_switch_pattern(func_addr)

                    for table in jump_tables:
                        table_pattern = PreservedPattern(
                            type=PatternType.JUMP_TABLE,
                            start_address=table.table_address,
                            end_address=table.table_address + (len(table.entries) * 8),
                            criticality=Criticality.PRESERVE,
                            source="switch_analysis",
                            metadata={
                                "case_count": table.case_count,
                                "is_dense": table.is_dense,
                                "bounds_register": table.bounds_check_register,
                            },
                        )
                        self._patterns.append(table_pattern)

                        for target in table.unique_targets:
                            target_pattern = PreservedPattern(
                                type=PatternType.JUMP_TABLE_ENTRY,
                                start_address=target,
                                end_address=target + 16,
                                criticality=Criticality.CAUTION,
                                source="switch_analysis",
                                metadata={"table_address": table.table_address},
                            )
                            self._patterns.append(target_pattern)

                    for jump in other_jumps:
                        if jump.jump_type in ("jumptable", "indirect"):
                            jump_pattern = PreservedPattern(
                                type=PatternType.INDIRECT_JUMP,
                                start_address=jump.address,
                                end_address=jump.address + 16,
                                criticality=Criticality.AVOID,
                                source="switch_analysis",
                                metadata={"jump_type": jump.jump_type},
                            )
                            self._patterns.append(jump_pattern)

                except Exception as e:
                    logger.debug(f"Jump table detection failed for 0x{func_addr:x}: {e}")

        except Exception as e:
            logger.debug(f"Jump table pattern detection failed: {e}")

    def _detect_plt_got_patterns(self) -> None:
        """Detect PLT thunks and GOT entries."""
        try:
            if self._switch_analyzer is None:
                self._switch_analyzer = SwitchTableAnalyzer(self.binary)

            plt_entries = self._switch_analyzer.detect_plt_got_thunks()

            for addr, info in plt_entries.items():
                pattern = PreservedPattern(
                    type=PatternType.PLT_THUNK,
                    start_address=addr,
                    end_address=addr + 16,
                    criticality=Criticality.PRESERVE,
                    source="plt_got_analysis",
                    metadata=info,
                )
                self._patterns.append(pattern)

        except Exception as e:
            logger.debug(f"PLT/GOT pattern detection failed: {e}")

    def _detect_tail_call_patterns(self) -> None:
        """Detect tail call patterns."""
        try:
            if self._switch_analyzer is None:
                self._switch_analyzer = SwitchTableAnalyzer(self.binary)

            functions = self.binary.get_functions()

            for func in functions:
                func_addr = func.get("offset", func.get("addr", 0))
                if func_addr == 0:
                    continue

                try:
                    tail_calls = self._switch_analyzer.detect_tail_calls(func_addr)

                    for jump_addr, target_addr in tail_calls:
                        pattern = PreservedPattern(
                            type=PatternType.TAIL_CALL,
                            start_address=jump_addr,
                            end_address=jump_addr + 5,
                            criticality=Criticality.AVOID,
                            source="tail_call_analysis",
                            metadata={"target_address": target_addr},
                        )
                        self._patterns.append(pattern)

                except Exception as e:
                    logger.debug(f"Tail call detection failed for 0x{func_addr:x}: {e}")

        except Exception as e:
            logger.debug(f"Tail call pattern detection failed: {e}")

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
