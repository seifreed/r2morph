"""
ABI enforcement hook for mutation passes.

Provides a reusable hook that can be integrated into any mutation pass
to enforce ABI invariants before and after mutations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.analysis.abi_checker import ABIChecker
from r2morph.analysis.abi_models import ABISpec, ABIViolation, ABIViolationType

logger = logging.getLogger(__name__)


class ABIViolationAction(Enum):
    """Action to take when ABI violation is detected."""

    WARN = "warn"
    BLOCK = "block"
    SKIP = "skip"


@dataclass
class ABICheckResult:
    """Result of ABI check."""

    valid: bool
    violations: list[ABIViolation] = field(default_factory=list)
    new_violations: list[ABIViolation] = field(default_factory=list)
    check_types: list[str] = field(default_factory=list)


@dataclass
class ABISnapshot:
    """Snapshot of ABI state before mutation."""

    function_address: int
    violations: list[ABIViolation] = field(default_factory=list)
    stack_alignment_ok: bool = True
    callee_saved_ok: bool = True
    red_zone_ok: bool = True
    shadow_space_ok: bool = True


@dataclass(frozen=True, slots=True)
class ABICheckOptions:
    stack_alignment: bool = True
    callee_saved: bool = True
    red_zone: bool = True
    shadow_space: bool = True


class ABIMutationHook:
    """
    Hook for enforcing ABI invariants in mutation passes.

    Usage:
        hook = ABIMutationHook(binary, action=ABIViolationAction.BLOCK)

        # Before mutation
        snapshot = hook.snapshot_function(func_addr)

        # ... apply mutations ...

        # After mutation
        result = hook.validate_function(func_addr, snapshot)
        if not result.valid:
            # Handle violation
    """

    def __init__(
        self,
        binary: Any,
        action: ABIViolationAction = ABIViolationAction.WARN,
        options: ABICheckOptions | None = None,
        abi_spec: ABISpec | None = None,
    ):
        """
        Initialize ABI mutation hook.

        Args:
            binary: Any being mutated
            action: Action to take on violation
            options: ABI checks to enable
            abi_spec: Optional ABI specification (auto-detected if None)
        """
        self.binary = binary
        self.action = action
        options = options or ABICheckOptions()
        self.check_stack_alignment = options.stack_alignment
        self.check_callee_saved = options.callee_saved
        self.check_red_zone = options.red_zone
        self.check_shadow_space = options.shadow_space
        self.checker = ABIChecker(binary, abi_spec)
        self._snapshots: dict[int, ABISnapshot] = {}
        self._total_violations: list[ABIViolation] = []
        self._blocked_functions: set[int] = set()

    @property
    def abi(self) -> ABISpec:
        """Get the ABI specification."""
        return self.checker.abi

    @property
    def total_violations(self) -> int:
        """Get total number of violations detected."""
        return len(self._total_violations)

    @property
    def blocked_functions(self) -> set[int]:
        """Get set of functions that were blocked from mutation."""
        return self._blocked_functions.copy()

    def snapshot_function(self, function_address: int) -> ABISnapshot:
        """
        Create a snapshot of ABI state before mutation.

        Args:
            function_address: Function address

        Returns:
            ABISnapshot with current state
        """
        violations = self._collect_violations(function_address)

        snapshot = ABISnapshot(
            function_address=function_address,
            violations=violations.copy(),
            stack_alignment_ok=len([v for v in violations if v.violation_type == ABIViolationType.STACK_ALIGNMENT])
            == 0,
            callee_saved_ok=len([v for v in violations if v.violation_type == ABIViolationType.CALLEE_SAVED_CLOBBER])
            == 0,
            red_zone_ok=True,
            shadow_space_ok=len([v for v in violations if v.violation_type == ABIViolationType.SHADOW_SPACE_VIOLATION])
            == 0,
        )

        self._snapshots[function_address] = snapshot

        return snapshot

    def validate_function(
        self,
        function_address: int,
        mutation_regions: list[tuple[int, int]] | None = None,
        snapshot: ABISnapshot | None = None,
    ) -> ABICheckResult:
        """
        Validate ABI after mutation.

        Args:
            function_address: Function address
            mutation_regions: Regions affected by mutation
            snapshot: Pre-mutation snapshot (uses stored if None)

        Returns:
            ABICheckResult with validation outcome
        """
        if snapshot is None:
            snapshot = self._snapshots.get(function_address)

        current_violations = self._collect_violations(function_address, mutation_regions)

        new_violations: list[ABIViolation] = []
        if snapshot:
            original_set = {(v.violation_type, v.location) for v in snapshot.violations}
            for v in current_violations:
                if (v.violation_type, v.location) not in original_set:
                    new_violations.append(v)
        else:
            new_violations = current_violations.copy()

        self._total_violations.extend(new_violations)

        result = ABICheckResult(
            valid=len(new_violations) == 0,
            violations=current_violations,
            new_violations=new_violations,
            check_types=self._enabled_check_types(),
        )

        if not result.valid and self.action == ABIViolationAction.BLOCK:
            self._blocked_functions.add(function_address)

        return result

    def _collect_violations(
        self,
        function_address: int,
        mutation_regions: list[tuple[int, int]] | None = None,
    ) -> list[ABIViolation]:
        violations: list[ABIViolation] = []
        if self.check_stack_alignment:
            violations.extend(self.checker.check_stack_alignment(function_address))
        if self.check_callee_saved:
            violations.extend(self.checker.check_callee_saved(function_address))
        if self.check_shadow_space:
            violations.extend(self.checker.check_shadow_space(function_address))
        if self.check_red_zone and mutation_regions:
            violations.extend(self.checker.check_red_zone(function_address, mutation_regions))
        return violations

    def _enabled_check_types(self) -> list[str]:
        checks = (
            (self.check_stack_alignment, "stack_alignment"),
            (self.check_callee_saved, "callee_saved"),
            (self.check_red_zone, "red_zone"),
            (self.check_shadow_space, "shadow_space"),
        )
        return [name for enabled, name in checks if enabled]

    def validate_region(
        self,
        start_address: int,
        end_address: int,
        function_address: int | None = None,
    ) -> ABICheckResult:
        """
        Validate ABI for a mutation region.

        Args:
            start_address: Start of mutation region
            end_address: End of mutation region
            function_address: Optional function address

        Returns:
            ABICheckResult
        """
        mutation_regions = [(start_address, end_address)]

        if function_address:
            return self.validate_function(function_address, mutation_regions)

        return ABICheckResult(
            valid=True,
            check_types=["region"],
        )

    def should_skip_mutation(self, function_address: int) -> bool:
        """
        Check if mutation should be skipped for a function.

        Args:
            function_address: Function address

        Returns:
            True if mutation should be skipped
        """
        if self.action != ABIViolationAction.SKIP:
            return False

        snapshot = self._snapshots.get(function_address)
        if not snapshot:
            return False

        return len(snapshot.violations) > 0

    def can_save_binary(self) -> bool:
        """
        Check if binary can be saved (no blocking violations).

        Returns:
            True if binary can be saved
        """
        if self.action != ABIViolationAction.BLOCK:
            return True

        return len(self._blocked_functions) == 0

    def get_diagnostics(self) -> dict[str, Any]:
        """
        Get diagnostic information about ABI violations.

        Returns:
            Dictionary with violation details
        """
        violations_by_type: dict[str, list[ABIViolation]] = {}
        for v in self._total_violations:
            key = v.violation_type.value
            if key not in violations_by_type:
                violations_by_type[key] = []
            violations_by_type[key].append(v)

        return {
            "abi_type": self.abi.abi_type.value,
            "total_violations": len(self._total_violations),
            "violations_by_type": {k: len(v) for k, v in violations_by_type.items()},
            "blocked_functions": list(self._blocked_functions),
            "action": self.action.value,
            "checks_enabled": {
                "stack_alignment": self.check_stack_alignment,
                "callee_saved": self.check_callee_saved,
                "red_zone": self.check_red_zone,
                "shadow_space": self.check_shadow_space,
            },
            "violations": [
                {
                    "type": v.violation_type.value,
                    "location": f"0x{v.location:x}",
                    "description": v.description,
                }
                for v in self._total_violations
            ],
        }

    def reset(self) -> None:
        """Reset hook state for new mutation session."""
        self._snapshots.clear()
        self._total_violations.clear()
        self._blocked_functions.clear()

    def log_violations(self, level: str = "warning") -> None:
        """
        Log all violations at specified level.

        Args:
            level: Log level (debug, info, warning, error)
        """
        log_func = getattr(logger, level, logger.warning)

        for v in self._total_violations:
            log_func(f"ABI violation ({v.violation_type.value}) at 0x{v.location:x}: {v.description}")

    def get_violations_for_function(self, function_address: int) -> list[ABIViolation]:
        """
        Get violations for a specific function.

        Args:
            function_address: Function address

        Returns:
            List of violations for the function
        """
        return [v for v in self._total_violations if v.location == function_address]


def create_abi_hook(
    binary: Any,
    strict: bool = False,
    checks: list[str] | None = None,
) -> ABIMutationHook:
    """
    Factory function to create an ABI hook with common configurations.

    Args:
        binary: Any being mutated
        strict: If True, block on violations; if False, warn
        checks: List of checks to enable (all if None)

    Returns:
        Configured ABIMutationHook
    """
    action = ABIViolationAction.BLOCK if strict else ABIViolationAction.WARN

    if checks is None:
        return ABIMutationHook(binary, action=action)

    return ABIMutationHook(
        binary,
        action=action,
        options=ABICheckOptions(
            stack_alignment="stack_alignment" in checks,
            callee_saved="callee_saved" in checks,
            red_zone="red_zone" in checks,
            shadow_space="shadow_space" in checks,
        ),
    )
