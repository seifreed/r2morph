"""
Hardened mutation pass base class.

Extends CFG-aware mutations with pattern preservation and integrity validation.
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from r2morph.mutations.cfg_aware import CFGAwareMutationPass, CFGAwareMutationResult

if TYPE_CHECKING:
    pass
from r2morph.analysis.pattern_preservation import (
    PatternPreservationManager,
    PatternType,
)
from r2morph.validation.cfg_integrity import (
    CFGIntegrityChecker,
    HardenedMutationValidator,
)

logger = logging.getLogger(__name__)


@dataclass
class HardenedMutationResult(CFGAwareMutationResult):
    """Result of a hardened mutation with pattern preservation."""

    patterns_preserved: int = 0
    patterns_avoided: int = 0
    integrity_violations: int = 0
    preservation_report: dict[str, Any] = field(default_factory=dict)
    integrity_report: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update(
            {
                "patterns_preserved": self.patterns_preserved,
                "patterns_avoided": self.patterns_avoided,
                "integrity_violations": self.integrity_violations,
                "preservation_report": self.preservation_report,
                "integrity_report": self.integrity_report,
            }
        )
        return base


class HardenedMutationPass(CFGAwareMutationPass):
    """
    Base class for hardened mutations with pattern preservation.

    Extends CFG-aware mutations with:
    - Automatic pattern preservation (exception handlers, jump tables, PLT)
    - Optional CFG integrity validation
    - Pre/post mutation analysis

    Subclasses should implement apply_hardened() instead of apply_cfg_aware().
    """

    def __init__(
        self,
        name: str = "hardened",
        enabled: bool = True,
        exclusion_radius: int = 8,
        min_safety_score: float = 0.5,
        preserve_patterns: bool = True,
        validate_integrity: bool = False,
    ):
        """
        Initialize hardened mutation pass.

        Args:
            name: Pass name
            enabled: Whether pass is enabled
            exclusion_radius: Radius around critical nodes to exclude
            min_safety_score: Minimum safety score for mutation sites
            preserve_patterns: Whether to preserve critical patterns
            validate_integrity: Whether to validate CFG integrity after mutation
        """
        super().__init__(
            name=name,
            exclusion_radius=exclusion_radius,
            min_safety_score=min_safety_score,
        )
        self.preserve_patterns = preserve_patterns
        self.validate_integrity = validate_integrity
        self._preservation_manager: PatternPreservationManager | None = None
        self._integrity_checker: CFGIntegrityChecker | None = None
        self._validator: HardenedMutationValidator | None = None
        self._current_function: int | None = None

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply the hardened mutation.

        Args:
            binary: Any to mutate

        Returns:
            Mutation result dictionary
        """
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        if self.preserve_patterns and self._preservation_manager is None:
            self._preservation_manager = PatternPreservationManager(binary)
            self._preservation_manager.analyze()

        if self.validate_integrity and self._integrity_checker is None:
            self._integrity_checker = CFGIntegrityChecker(binary)

        result = HardenedMutationResult(
            success=True,
        )

        functions = binary.get_functions()

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            self._current_function = func_addr

            if self.validate_integrity and self._integrity_checker:
                self._integrity_checker.create_snapshot(func_addr)

            try:
                func_result = self._apply_to_function(binary, func_addr)

                if isinstance(func_result, dict):
                    mutations_list: list[Any] = result.metadata.setdefault("mutations", [])
                    mutations_list.extend(func_result.get("mutations", []))
                    result.safe_mutations += func_result.get("safe_mutations", 0)
                    result.skipped_mutations += func_result.get("skipped_mutations", 0)
                    result.patterns_preserved += func_result.get("patterns_preserved", 0)
                    result.patterns_avoided += func_result.get("patterns_avoided", 0)

            except Exception as e:
                logger.error(f"Failed to apply hardened mutation to 0x{func_addr:x}: {e}")

            if self.validate_integrity and self._integrity_checker:
                integrity_report = self._integrity_checker.validate_integrity(func_addr)
                result.integrity_violations += len(integrity_report.violations)
                result.integrity_report.update(integrity_report.to_dict())
                self._integrity_checker.clear_snapshot(func_addr)

        if self._preservation_manager:
            result.preservation_report = self._preservation_manager.report()

        return result.to_dict()

    def _apply_to_function(self, binary: Any, func_addr: int) -> dict[str, Any]:
        """
        Apply mutation to a single function.

        Args:
            binary: Any to mutate
            func_addr: Function address

        Returns:
            Function-level mutation result
        """
        from r2morph.analysis.cfg import CFGBuilder

        func_name = f"func_{func_addr:x}"

        try:
            builder = CFGBuilder(binary)
            cfg = builder.build_cfg(func_addr, func_name)
        except Exception as e:
            logger.debug(f"Failed to build CFG for 0x{func_addr:x}: {e}")
            return {"mutations": [], "safe_mutations": 0, "skipped_mutations": 0}

        safe_regions = self._get_safe_regions_with_patterns(func_addr)

        exclusion_zones = []
        if self._preservation_manager:
            func_zones = [
                z
                for z in self._preservation_manager.get_exclusion_zones()
                if z.expanded_start < func_addr + 0x10000 and z.expanded_end > func_addr
            ]
            exclusion_zones = func_zones

        result = self.apply_hardened(
            binary,
            cfg,
            safe_regions,
            exclusion_zones,
        )

        return result

    def _get_safe_regions_with_patterns(self, func_addr: int) -> list[tuple[int, int]]:
        """
        Get safe regions excluding pattern preservation zones.

        Args:
            func_addr: Function address

        Returns:
            List of (start, end) safe region tuples
        """
        if not self._preservation_manager:
            return []

        return self._preservation_manager.get_safe_addresses(
            func_addr,
            func_addr + 0x10000,
            min_gap=4,
        )

    def apply_cfg_aware(
        self,
        binary: Any,
        cfg: Any,
        safe_regions: list[Any],
    ) -> dict[str, Any]:
        """Delegate to apply_hardened with empty exclusion zones."""
        return self.apply_hardened(
            binary, cfg, [(r.start, r.end) if hasattr(r, "start") else r for r in safe_regions], []
        )

    @abstractmethod
    def apply_hardened(
        self,
        binary: Any,
        cfg: Any,
        safe_regions: list[tuple[int, int]],
        exclusion_zones: list[Any],
    ) -> dict[str, Any]:
        """
        Apply the mutation with pattern preservation.

        Subclasses must implement this method.

        Args:
            binary: Any to mutate
            cfg: Control flow graph
            safe_regions: Safe (start, end) address ranges
            exclusion_zones: Exclusion zones to avoid

        Returns:
            Dictionary with mutation results
        """
        pass

    def should_preserve(self, address: int) -> bool:
        """
        Check if address should be preserved.

        Args:
            address: Address to check

        Returns:
            True if address must be preserved
        """
        if self._preservation_manager:
            return self._preservation_manager.should_preserve(address)
        return False

    def should_avoid_pattern(self, address: int) -> bool:
        """
        Check if address should be avoided due to pattern preservation.

        Args:
            address: Address to check

        Returns:
            True if address should be avoided
        """
        if self._preservation_manager:
            return self._preservation_manager.should_avoid(address)
        return False

    def get_preserved_pattern_at(self, address: int) -> Any:
        """
        Get preserved pattern at address.

        Args:
            address: Address to query

        Returns:
            PreservedPattern if found, None otherwise
        """
        if self._preservation_manager:
            return self._preservation_manager.get_pattern_at(address)
        return None

    def get_exclusion_zones_for_type(self, pattern_type: PatternType) -> list[Any]:
        """
        Get exclusion zones for a specific pattern type.

        Args:
            pattern_type: Type of pattern

        Returns:
            List of exclusion zones
        """
        if self._preservation_manager:
            return self._preservation_manager.get_exclusion_zones_for_type(pattern_type)
        return []


class HardenedControlFlowFlattening(HardenedMutationPass):
    """
    Hardened control flow flattening with pattern preservation.

    Preserves critical patterns (jump tables, exception handlers, PLT/GOT)
    during CFF transformations.
    """

    def __init__(
        self,
        name: str = "hardened_cff",
        enabled: bool = True,
        preserve_patterns: bool = True,
        validate_integrity: bool = True,
        max_functions: int = 5,
        min_blocks: int = 3,
        probability: float = 0.5,
    ):
        """
        Initialize hardened CFF pass.

        Args:
            name: Pass name
            enabled: Whether pass is enabled
            preserve_patterns: Whether to preserve critical patterns
            validate_integrity: Whether to validate integrity
            max_functions: Maximum functions to transform
            min_blocks: Minimum blocks required
            probability: Transformation probability
        """
        super().__init__(
            name=name,
            enabled=enabled,
            preserve_patterns=preserve_patterns,
            validate_integrity=validate_integrity,
        )
        self.max_functions = max_functions
        self.min_blocks = min_blocks
        self.probability = probability

    def apply_hardened(
        self,
        binary: Any,
        cfg: Any,
        safe_regions: list[tuple[int, int]],
        exclusion_zones: list[Any],
    ) -> dict[str, Any]:
        """
        Apply hardened CFF transformation.

        Args:
            binary: Any to mutate
            cfg: Control flow graph
            safe_regions: Safe address ranges
            exclusion_zones: Exclusion zones

        Returns:
            Mutation result dictionary
        """
        import random

        mutations: list[dict[str, Any]] = []
        safe_mutations = 0
        skipped_mutations = 0
        patterns_preserved = 0
        patterns_avoided = 0

        def _build_result() -> dict[str, Any]:
            return {
                "mutations": mutations,
                "safe_mutations": safe_mutations,
                "skipped_mutations": skipped_mutations,
                "patterns_preserved": patterns_preserved,
                "patterns_avoided": patterns_avoided,
            }

        if random.random() > self.probability:
            return _build_result()

        blocks = list(cfg.blocks.items()) if hasattr(cfg, "blocks") else []

        if len(blocks) < self.min_blocks:
            return _build_result()

        for block_addr, block in blocks:
            if self.should_avoid_pattern(block_addr):
                skipped_mutations += 1
                patterns_avoided += 1
                continue

            if self.should_preserve(block_addr):
                patterns_preserved += 1
                continue

            in_safe_region = any(start <= block_addr < end for start, end in safe_regions)

            if not in_safe_region and safe_regions:
                skipped_mutations += 1
                continue

            mutation = self._try_flatten_block(binary, block_addr, block, exclusion_zones)
            if mutation:
                mutations.append(mutation)
                safe_mutations += 1

        return _build_result()

    def _try_flatten_block(
        self,
        binary: Any,
        block_addr: int,
        block: Any,
        exclusion_zones: list[Any],
    ) -> dict[str, Any] | None:
        """
        Try to flatten a block.

        Args:
            binary: Any to mutate
            block_addr: Block address
            block: Block object
            exclusion_zones: Exclusion zones

        Returns:
            Mutation info if successful, None otherwise
        """
        for zone in exclusion_zones:
            if zone.contains(block_addr):
                return None

        return {
            "type": "cff",
            "address": f"0x{block_addr:x}",
            "description": "Control flow flattening candidate",
        }


class HardenedOpaquePredicates(HardenedMutationPass):
    """
    Hardened opaque predicate insertion with pattern preservation.

    Safely inserts opaque predicates avoiding critical patterns.
    """

    def __init__(
        self,
        name: str = "hardened_opaque",
        enabled: bool = True,
        preserve_patterns: bool = True,
        validate_integrity: bool = True,
        density: float = 0.3,
    ):
        """
        Initialize hardened opaque predicates pass.

        Args:
            name: Pass name
            enabled: Whether pass is enabled
            preserve_patterns: Whether to preserve critical patterns
            validate_integrity: Whether to validate integrity
            density: Predicate density (0.0 to 1.0)
        """
        super().__init__(
            name=name,
            enabled=enabled,
            preserve_patterns=preserve_patterns,
            validate_integrity=validate_integrity,
        )
        self.density = density

    def apply_hardened(
        self,
        binary: Any,
        cfg: Any,
        safe_regions: list[tuple[int, int]],
        exclusion_zones: list[Any],
    ) -> dict[str, Any]:
        """
        Apply hardened opaque predicate insertion.

        Args:
            binary: Any to mutate
            cfg: Control flow graph
            safe_regions: Safe address ranges
            exclusion_zones: Exclusion zones

        Returns:
            Mutation result dictionary
        """
        all_mutations: list[dict[str, Any]] = []
        safe_mutations = 0
        skipped_mutations = 0
        patterns_preserved = 0
        patterns_avoided = 0

        blocks = list(cfg.blocks.items()) if hasattr(cfg, "blocks") else []

        for block_addr, block in blocks:
            if self.should_avoid_pattern(block_addr):
                skipped_mutations += 1
                patterns_avoided += 1
                continue

            if self.should_preserve(block_addr):
                patterns_preserved += 1
                continue

            in_safe_region = any(start <= block_addr < end for start, end in safe_regions)

            if not in_safe_region and safe_regions:
                skipped_mutations += 1
                continue

            found_mutations = self._find_opaque_opportunities(binary, block_addr, block, exclusion_zones)
            all_mutations.extend(found_mutations)
            safe_mutations += len(found_mutations)

        return {
            "mutations": all_mutations,
            "safe_mutations": safe_mutations,
            "skipped_mutations": skipped_mutations,
            "patterns_preserved": patterns_preserved,
            "patterns_avoided": patterns_avoided,
        }

    def _find_opaque_opportunities(
        self,
        binary: Any,
        block_addr: int,
        block: Any,
        exclusion_zones: list[Any],
    ) -> list[dict[str, Any]]:
        """
        Find opportunities for opaque predicate insertion.

        Args:
            binary: Any to mutate
            block_addr: Block address
            block: Block object
            exclusion_zones: Exclusion zones

        Returns:
            List of mutation opportunities
        """
        import random

        opportunities: list[dict[str, Any]] = []

        if not hasattr(block, "instructions"):
            return opportunities

        for i, insn in enumerate(block.instructions):
            insn_addr = insn.get("offset", insn.get("addr", 0))

            if self.should_avoid_pattern(insn_addr):
                continue

            in_zone = any(zone.contains(insn_addr) for zone in exclusion_zones)
            if in_zone:
                continue

            if random.random() < self.density:
                opportunities.append(
                    {
                        "type": "opaque_predicate",
                        "address": f"0x{insn_addr:x}",
                        "position": i,
                    }
                )

        return opportunities


def create_hardened_cff_pass(**kwargs: Any) -> HardenedControlFlowFlattening:
    """
    Create a hardened CFF pass.

    Args:
        **kwargs: Pass arguments

    Returns:
        HardenedControlFlowFlattening instance
    """
    return HardenedControlFlowFlattening(**kwargs)


def create_hardened_opaque_pass(**kwargs: Any) -> HardenedOpaquePredicates:
    """
    Create a hardened opaque predicates pass.

    Args:
        **kwargs: Pass arguments

    Returns:
        HardenedOpaquePredicates instance
    """
    return HardenedOpaquePredicates(**kwargs)
