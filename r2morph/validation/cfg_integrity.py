import logging
from typing import Any

from r2morph.analysis.cfg import CFGBuilder
from r2morph.analysis.pattern_preservation import PatternPreservationManager
from r2morph.core.binary import Binary
from r2morph.validation.cfg_integrity_helpers import create_cfg_snapshot, validate_cfg_snapshot
from r2morph.validation.cfg_integrity_models import (
    CFGSnapshot,
    IntegrityReport,
    IntegrityStatus,
    IntegrityViolation,
)
from r2morph.validation.cfg_integrity_models import (
    IntegrityCheck as _IntegrityCheck,
)

logger = logging.getLogger(__name__)

IntegrityCheck = _IntegrityCheck


class CFGIntegrityChecker:
    """
    Validates CFG integrity after mutations.

    Takes snapshots before mutation and validates after to ensure
    critical control flow properties are preserved.
    """

    def __init__(self, binary: Binary, preserve_patterns: bool = True) -> None:
        self.binary = binary
        self.preserve_patterns = preserve_patterns
        self._snapshots: dict[int, CFGSnapshot] = {}
        self._preservation_manager: PatternPreservationManager | None = None
        self._cfg_builder = CFGBuilder(binary)

    def create_snapshot(self, function_address: int) -> CFGSnapshot | None:
        snapshot = create_cfg_snapshot(self._cfg_builder, self._preservation_manager, function_address)
        if snapshot is not None:
            self._snapshots[function_address] = snapshot
        else:
            logger.debug(f"Failed to create snapshot for 0x{function_address:x}")
        return snapshot

    def validate_integrity(self, function_address: int) -> IntegrityReport:
        """
        Validate CFG integrity after mutation.

        Args:
            function_address: Function address

        Returns:
            IntegrityReport with validation results
        """
        snapshot = self._snapshots.get(function_address)

        if not snapshot:
            return IntegrityReport(
                valid=False,
                violations=[
                    IntegrityViolation(
                        status=IntegrityStatus.INVALID_TARGET,
                        address=function_address,
                        description="No snapshot found for function",
                        severity="error",
                    )
                ],
            )

        return validate_cfg_snapshot(snapshot)

    def analyze_preservation_before(
        self,
        function_address: int,
    ) -> dict[str, Any] | None:
        """
        Analyze patterns that need preservation before mutation.

        Args:
            function_address: Function address

        Returns:
            Dictionary with preservation analysis
        """
        if self._preservation_manager is None:
            self._preservation_manager = PatternPreservationManager(self.binary)
            self._preservation_manager.analyze()

        patterns = self._preservation_manager.get_patterns_in_range(
            function_address,
            function_address + 0x10000,
        )

        zones = self._preservation_manager.get_exclusion_zones()

        func_zones = [
            z for z in zones if z.expanded_start < function_address + 0x10000 and z.expanded_end > function_address
        ]

        return {
            "function_address": function_address,
            "patterns_detected": len(patterns),
            "patterns": [p.to_dict() for p in patterns],
            "exclusion_zones": [z.to_dict() for z in func_zones],
            "safe_regions": self._preservation_manager.get_safe_addresses(
                function_address,
                function_address + 0x10000,
            ),
        }

    def clear_snapshot(self, function_address: int) -> None:
        """Clear a snapshot after validation."""
        if function_address in self._snapshots:
            del self._snapshots[function_address]

    def clear_all_snapshots(self) -> None:
        """Clear all stored snapshots."""
        self._snapshots.clear()


class HardenedMutationValidator:
    """
    Combined validator for hardened mutations.

    Combines pattern preservation and CFG integrity checks.
    """

    def __init__(self, binary: Binary) -> None:
        self.binary = binary
        self._preservation_manager: PatternPreservationManager | None = None
        self._integrity_checker = CFGIntegrityChecker(binary)

    def pre_mutation_analysis(self, function_address: int) -> dict[str, Any]:
        """
        Perform pre-mutation analysis.

        Args:
            function_address: Function address

        Returns:
            Pre-mutation analysis results
        """
        if self._preservation_manager is None:
            self._preservation_manager = PatternPreservationManager(self.binary)
            self._preservation_manager.analyze()

        snapshot = self._integrity_checker.create_snapshot(function_address)

        preservation = self._preservation_manager.get_patterns_in_range(
            function_address,
            function_address + 0x10000,
        )

        safe_addresses = self._preservation_manager.get_safe_addresses(
            function_address,
            function_address + 0x10000,
        )

        return {
            "function_address": function_address,
            "snapshot_created": snapshot is not None,
            "patterns_to_preserve": len(preservation),
            "safe_address_ranges": len(safe_addresses),
            "exclusion_zones": len(
                [z for z in self._preservation_manager.get_exclusion_zones() if z.expanded_start >= function_address]
            ),
        }

    def post_mutation_validation(self, function_address: int) -> dict[str, Any]:
        """
        Perform post-mutation validation.

        Args:
            function_address: Function address

        Returns:
            Validation results
        """
        integrity_report = self._integrity_checker.validate_integrity(function_address)

        result = {
            "function_address": function_address,
            "valid": integrity_report.valid,
            "violations": len(integrity_report.violations),
            "violation_details": [v.to_dict() for v in integrity_report.violations],
            "checks_run": len(integrity_report.checks_run),
        }

        self._integrity_checker.clear_snapshot(function_address)

        return result

    def get_preservation_manager(self) -> PatternPreservationManager:
        """Get the preservation manager."""
        if self._preservation_manager is None:
            self._preservation_manager = PatternPreservationManager(self.binary)
            self._preservation_manager.analyze()
        return self._preservation_manager
