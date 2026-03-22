"""
Base class for ABI-aware mutation passes.

Provides integration of ABI mutation hooks into the mutation pipeline.
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from r2morph.mutations.base import MutationPass, MutationRecord

if TYPE_CHECKING:
    from r2morph.protocols import BinaryAccessProtocol
from r2morph.mutations.abi_hook import (
    ABIMutationHook,
    ABICheckResult,
    ABIViolationAction,
    ABISnapshot,
)

logger = logging.getLogger(__name__)


@dataclass
class ABIResult:
    """Result of ABI validation for a mutation pass."""

    valid: bool
    violations_before: int = 0
    violations_after: int = 0
    new_violations: int = 0
    blocked_functions: list[int] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)


class ABIValidationError(Exception):
    """Exception raised when ABI validation fails."""

    def __init__(self, message: str, violations: list[Any] | None = None):
        super().__init__(message)
        self.violations = violations or []


class ABIAwareMutationPass(MutationPass):
    """
    Base class for mutation passes with ABI enforcement.

    Subclasses should implement apply_abi_aware() instead of apply().

    Features:
    - Pre-mutation ABI snapshot
    - Post-mutation ABI validation
    - Violation blocking or warning
    - Per-function ABI tracking
    """

    def __init__(
        self,
        name: str,
        config: dict[str, Any] | None = None,
        enforce_abi: bool = True,
        abi_action: str = "warn",
        abi_checks: list[str] | None = None,
    ):
        """
        Initialize ABI-aware mutation pass.

        Args:
            name: Pass name
            config: Configuration dictionary
            enforce_abi: Whether to enable ABI checking
            abi_action: Action on violation ("warn", "block", "skip")
            abi_checks: List of ABI checks to enable
        """
        super().__init__(name=name, config=config)
        self.enforce_abi = enforce_abi
        self.abi_action = (
            ABIViolationAction(abi_action) if abi_action in ("warn", "block", "skip") else ABIViolationAction.WARN
        )
        self.abi_checks = abi_checks
        self._abi_hook: ABIMutationHook | None = None
        self._abi_result: ABIResult | None = None
        self._abi_snapshots: dict[int, ABISnapshot] = {}

    def run(self, binary: Any) -> dict[str, Any]:
        """
        Run the mutation pass with ABI enforcement.

        Args:
            binary: Any instance

        Returns:
            Mutation result dictionary
        """
        if not self.enabled:
            logger.info(f"Pass {self.name} is disabled, skipping")
            return {"mutations_applied": 0, "skipped": True}

        if not self.enforce_abi:
            return super().run(binary)

        self._abi_hook = ABIMutationHook(
            binary,
            action=self.abi_action,
            check_stack_alignment="stack_alignment" in (self.abi_checks or ["stack_alignment", "callee_saved"]),
            check_callee_saved="callee_saved" in (self.abi_checks or ["stack_alignment", "callee_saved"]),
            check_red_zone="red_zone" in (self.abi_checks or []),
            check_shadow_space="shadow_space" in (self.abi_checks or []),
        )

        self._abi_result = ABIResult(
            valid=True,
            violations_before=0,
            violations_after=0,
            new_violations=0,
            blocked_functions=[],
            diagnostics={},
        )

        logger.debug(f"Running ABI-aware mutation pass: {self.name}")

        try:
            result = super().run(binary)

            if self._abi_hook:
                self._abi_result.violations_after = self._abi_hook.total_violations
                self._abi_result.blocked_functions = list(self._abi_hook.blocked_functions)
                self._abi_result.diagnostics = self._abi_hook.get_diagnostics()

                can_save = self._abi_hook.can_save_binary()
                self._abi_result.valid = can_save

                if not can_save and self.abi_action == ABIViolationAction.BLOCK:
                    result["abi_blocked"] = True
                    result["abi_violations"] = self._abi_result.violations_after
                    result["abi_diagnostics"] = self._abi_result.diagnostics
                    result["success"] = False
                    result["error"] = "ABI violations detected, output blocked"

                result["abi_result"] = {
                    "valid": self._abi_result.valid,
                    "violations_before": self._abi_result.violations_before,
                    "violations_after": self._abi_result.violations_after,
                    "new_violations": self._abi_result.new_violations,
                    "blocked_functions": [f"0x{addr:x}" for addr in self._abi_result.blocked_functions],
                }

            return result

        except Exception as e:
            logger.error(f"Error in ABI-aware mutation pass {self.name}: {e}")
            raise

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply mutations with ABI checking.

        This method wraps apply_abi_aware() with ABI enforcement.

        Args:
            binary: Any instance

        Returns:
            Mutation result dictionary
        """
        if not self.enforce_abi or self._abi_hook is None:
            return self.apply_abi_aware(binary, abi_hook=None)

        functions = binary.get_functions()
        result = {
            "mutations": [],
            "mutations_applied": 0,
            "functions_processed": 0,
            "functions_blocked": 0,
        }

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            if func_addr == 0:
                continue

            snapshot = self._abi_hook.snapshot_function(func_addr)
            self._abi_snapshots[func_addr] = snapshot
            self._abi_result.violations_before += len(snapshot.violations)

            if self._abi_hook.should_skip_mutation(func_addr):
                result["functions_blocked"] += 1
                continue

            func_result = self.apply_to_function_abi_aware(binary, func_addr, snapshot)

            if func_result:
                validation = self._abi_hook.validate_function(func_addr)
                if not validation.valid:
                    self._abi_result.new_violations += len(validation.new_violations)

                    if self.abi_action == ABIViolationAction.BLOCK:
                        logger.warning(f"Function 0x{func_addr:x} blocked due to ABI violations")
                        result["functions_blocked"] += 1
                        continue

                result["mutations"].extend(func_result.get("mutations", []))
                result["mutations_applied"] += func_result.get("mutations_applied", 0)

            result["functions_processed"] += 1

        return result

    @abstractmethod
    def apply_abi_aware(
        self,
        binary: Any,
        abi_hook: ABIMutationHook | None,
    ) -> dict[str, Any]:
        """
        Apply mutations with ABI awareness.

        Subclasses should implement this method.

        Args:
            binary: Any instance
            abi_hook: ABI mutation hook for checking

        Returns:
            Mutation result dictionary
        """
        pass

    def apply_to_function_abi_aware(
        self,
        binary: Any,
        function_address: int,
        abi_snapshot: ABISnapshot,
    ) -> dict[str, Any] | None:
        """
        Apply mutations to a single function with ABI checking.

        Override this method for function-level mutations.

        Args:
            binary: Any instance
            function_address: Function address
            abi_snapshot: Pre-mutation ABI snapshot

        Returns:
            Mutation result for this function, or None to skip
        """
        return {"mutations": [], "mutations_applied": 0}

    def snapshot_abi(self, function_address: int) -> ABISnapshot | None:
        """
        Create an ABI snapshot for a function.

        Args:
            function_address: Function address

        Returns:
            ABISnapshot or None if not enforcing ABI
        """
        if not self.enforce_abi or self._abi_hook is None:
            return None

        snapshot = self._abi_hook.snapshot_function(function_address)
        self._abi_snapshots[function_address] = snapshot
        return snapshot

    def validate_abi(
        self,
        function_address: int,
        mutation_regions: list[tuple[int, int]] | None = None,
    ) -> ABICheckResult | None:
        """
        Validate ABI for a function after mutation.

        Args:
            function_address: Function address
            mutation_regions: Regions affected by mutation

        Returns:
            ABICheckResult or None if not enforcing ABI
        """
        if not self.enforce_abi or self._abi_hook is None:
            return None

        snapshot = self._abi_snapshots.get(function_address)
        result = self._abi_hook.validate_function(function_address, mutation_regions, snapshot)

        if not result.valid:
            self._abi_result.new_violations += len(result.new_violations)

        return result

    def can_continue_after_abi_check(self, function_address: int) -> bool:
        """
        Check if mutation can continue for a function after ABI check.

        Args:
            function_address: Function address

        Returns:
            True if mutation can continue
        """
        if not self.enforce_abi or self._abi_hook is None:
            return True

        if self._abi_hook.should_skip_mutation(function_address):
            return False

        if self.abi_action == ABIViolationAction.BLOCK:
            if function_address in self._abi_hook.blocked_functions:
                return False

        return True

    def get_abi_diagnostics(self) -> dict[str, Any]:
        """
        Get ABI diagnostics for the last run.

        Returns:
            Dictionary with ABI diagnostics
        """
        if self._abi_hook is None:
            return {"enabled": False}

        return self._abi_hook.get_diagnostics()

    def get_abi_result(self) -> ABIResult | None:
        """
        Get ABI result for the last run.

        Returns:
            ABIResult or None
        """
        return self._abi_result


def create_abi_aware_pass(
    pass_class: type,
    name: str,
    config: dict[str, Any] | None = None,
    enforce_abi: bool = True,
    abi_action: str = "warn",
    abi_checks: list[str] | None = None,
) -> ABIAwareMutationPass:
    """
    Factory function to create an ABI-aware mutation pass.

    Args:
        pass_class: Mutation pass class to wrap
        name: Pass name
        config: Configuration dictionary
        enforce_abi: Whether to enable ABI checking
        abi_action: Action on violation
        abi_checks: List of ABI checks to enable

    Returns:
        ABI-aware mutation pass instance
    """
    pass_instance = pass_class(name=name, config=config)

    abi_pass = ABIAwareMutationPass(
        name=name,
        config=config,
        enforce_abi=enforce_abi,
        abi_action=abi_action,
        abi_checks=abi_checks,
    )

    abi_pass.apply = pass_instance.apply

    return abi_pass
