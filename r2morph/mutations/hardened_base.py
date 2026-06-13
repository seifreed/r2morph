"""Hardened mutation pass base class."""

# ruff: noqa: I001

from __future__ import annotations

import logging
from abc import abstractmethod
from typing import Any

from r2morph.analysis.pattern_preservation import (
    PatternPreservationManager,
    PatternType,
)
from r2morph.mutations.cfg_aware import CFGAwareMutationPass
from r2morph.mutations.hardened_models import HardenedMutationResult
from r2morph.validation.cfg_integrity import (
    CFGIntegrityChecker,
    HardenedMutationValidator,
)

logger = logging.getLogger(__name__)


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

        return self.apply_hardened(binary, cfg, safe_regions, exclusion_zones)

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
            binary,
            cfg,
            [(r.start, r.end) if hasattr(r, "start") else r for r in safe_regions],
            [],
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
        """
        pass

    def should_preserve(self, address: int) -> bool:
        if self._preservation_manager:
            return self._preservation_manager.should_preserve(address)
        return False

    def should_avoid_pattern(self, address: int) -> bool:
        if self._preservation_manager:
            return self._preservation_manager.should_avoid(address)
        return False

    def get_preserved_pattern_at(self, address: int) -> Any:
        if self._preservation_manager:
            return self._preservation_manager.get_pattern_at(address)
        return None

    def get_exclusion_zones_for_type(self, pattern_type: PatternType) -> list[Any]:
        if self._preservation_manager:
            return self._preservation_manager.get_exclusion_zones_for_type(pattern_type)
        return []


from r2morph.mutations.hardened_cff import (  # noqa: E402,F401
    create_hardened_cff_pass,
    HardenedControlFlowFlattening,
)
from r2morph.mutations.hardened_opaque import (  # noqa: E402,F401
    create_hardened_opaque_pass,
    HardenedOpaquePredicates,
)


__all__ = [
    "HardenedMutationPass",
    "HardenedMutationResult",
    "HardenedControlFlowFlattening",
    "HardenedOpaquePredicates",
    "create_hardened_cff_pass",
    "create_hardened_opaque_pass",
]
