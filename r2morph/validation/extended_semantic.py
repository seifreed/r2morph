"""
Extended semantic validation with improved limits and caching.

This module extends the base SemanticValidator with:
- Increased state and step limits
- Constraint caching for reuse
- Better state merging strategies
- Function and loop-level validation
"""

import logging
import time
from typing import Any

from r2morph.analysis.cfg import ControlFlowGraph
from r2morph.core.binary import Binary
from r2morph.validation.constraint_cache import (
    ConstraintCache as _ConstraintCache,
)
from r2morph.validation.constraint_cache import (
    ConstraintCacheEntry as _ConstraintCacheEntry,
)
from r2morph.validation.extended_semantic_models import ValidationResult
from r2morph.validation.extended_semantic_validation import ExtendedSemanticValidationMixin
from r2morph.validation.semantic import MutationRegion, SemanticValidator, ValidationMode, ValidationResultStatus
from r2morph.validation.semantic_report_models import SemanticValidationResult
from r2morph.validation.state_merging import (
    ANGR_AVAILABLE as _ANGR_AVAILABLE,
)
from r2morph.validation.state_merging import (
    ImprovedStateMerging as _ImprovedStateMerging,
)

logger = logging.getLogger(__name__)


ConstraintCache = _ConstraintCache
ConstraintCacheEntry = _ConstraintCacheEntry
ImprovedStateMerging = _ImprovedStateMerging
ANGR_AVAILABLE = _ANGR_AVAILABLE


class ExtendedSemanticValidator(ExtendedSemanticValidationMixin, SemanticValidator):
    """
    Extended semantic validator with improved capabilities.

    Features:
    - Higher state and step limits
    - Constraint caching
    - Better state merging
    - Function and loop-level validation
    """

    def __init__(
        self,
        binary: Binary,
        mode: ValidationMode = ValidationMode.STANDARD,
        max_states: int = 10000,
        max_steps: int = 500,
        use_constraint_cache: bool = True,
        merge_interval: int = 100,
    ) -> None:
        """
        Initialize extended semantic validator.

        Args:
            binary: Binary to validate
            mode: Validation mode
            max_states: Maximum concurrent states (increased from 1000)
            max_steps: Maximum execution steps (increased from default)
            use_constraint_cache: Whether to use constraint caching
            merge_interval: Number of steps between state merges
        """
        super().__init__(binary, mode)

        self._angr_available = ANGR_AVAILABLE
        self.max_states = max_states
        self.max_steps = max_steps
        self.use_constraint_cache = use_constraint_cache
        self.merge_interval = merge_interval

        self._constraint_cache = ConstraintCache() if use_constraint_cache else None
        self._state_merger = ImprovedStateMerging()
        self._validation_cache: dict[int, ValidationResult] = {}

    def validate_function_semantics(
        self,
        function_address: int,
        cfg: ControlFlowGraph | None = None,
    ) -> SemanticValidationResult:
        """
        Validate semantics of an entire function.

        Args:
            function_address: Function address
            cfg: Optional control flow graph

        Returns:
            SemanticValidationResult
        """
        start_time = time.time()

        region = MutationRegion(
            start_address=function_address,
            end_address=function_address,
            original_bytes=b"",
            mutated_bytes=b"",
            pass_name="function_semantic_validation",
            function_address=function_address,
        )

        result = SemanticValidationResult(
            region=region,
            status=ValidationResultStatus.PASS,
            symbolic_status="not_requested",
        )

        try:
            if self._angr_available:
                self._validate_function_with_symbolic(function_address, result, cfg)
            else:
                self._validate_function_with_invariants(function_address, result)

        except Exception as e:
            logger.error(f"Function semantic validation failed: {e}")
            result.status = ValidationResultStatus.ERROR
            result.error_message = str(e)

        result.execution_time_seconds = time.time() - start_time
        return result

    def _merge_active_states(self, simgr: Any) -> None:
        """Merge active states in simulation manager."""
        if not ANGR_AVAILABLE:
            return

        active = simgr.active
        if len(active) <= 1:
            return

        merged = []
        remaining = []

        pc_groups: dict[int, list[Any]] = {}
        for state in active:
            try:
                pc = state.addr
                if pc not in pc_groups:
                    pc_groups[pc] = []
                pc_groups[pc].append(state)
            except Exception:
                remaining.append(state)

        for pc, states in pc_groups.items():
            if len(states) == 1:
                merged.append(states[0])
            elif len(states) <= self._state_merger.k_limit:
                merged_state = self._state_merger.merge_states(states)
                if merged_state:
                    merged.append(merged_state)
                else:
                    merged.extend(states)
            else:
                merged.extend(states[: self._state_merger.k_limit])

        merged.extend(remaining)
        simgr.active = merged

    def clear_cache(self) -> None:
        """Clear all caches."""
        if self._constraint_cache:
            self._constraint_cache.clear()
        self._validation_cache.clear()

    def get_cache_statistics(self) -> dict[str, Any]:
        """Get cache statistics."""
        stats: dict[str, Any] = {
            "validation_cache_size": len(self._validation_cache),
        }

        if self._constraint_cache:
            stats["constraint_cache"] = (
                self._constraint_cache.get_statistics() if self._constraint_cache is not None else {}
            )

        return stats


def create_extended_validator(
    binary: Binary,
    mode: str = "standard",
    **kwargs: Any,
) -> ExtendedSemanticValidator:
    """
    Create an extended semantic validator.

    Args:
        binary: Binary to validate
        mode: Validation mode (fast/standard/thorough)
        **kwargs: Additional arguments

    Returns:
        ExtendedSemanticValidator instance
    """
    mode_enum = ValidationMode(mode)

    thorough_defaults: dict[str, Any] = {
        "max_states": 10000,
        "max_steps": 500,
        "merge_interval": 100,
    }

    standard_defaults: dict[str, Any] = {
        "max_states": 5000,
        "max_steps": 250,
        "merge_interval": 50,
    }

    fast_defaults: dict[str, Any] = {
        "max_states": 1000,
        "max_steps": 100,
        "merge_interval": 25,
    }

    if mode_enum == ValidationMode.THOROUGH:
        defaults = thorough_defaults
    elif mode_enum == ValidationMode.FAST:
        defaults = fast_defaults
    else:
        defaults = standard_defaults

    defaults.update(kwargs)

    return ExtendedSemanticValidator(
        binary=binary,
        mode=mode_enum,
        **defaults,
    )
