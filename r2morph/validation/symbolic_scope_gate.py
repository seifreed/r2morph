"""Symbolic-scope gate extracted from SymbolicValidator (clean-arch slice 1a).

Decides whether a binary + pass_result falls inside the experimental
symbolic scope and estimates a bounded per-region step budget. Pure
predicate logic — no angr. Imported lazily by SymbolicValidator.__init__
(composition root); the dependency on r2morph.validation.manager
(_parse_address) is the same one symbolic_validator.py already carries
and is not a circular import (manager does not import this module).
"""

from __future__ import annotations

from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.symbolic_scope_policy import (
    build_scope_metadata,
    check_scope_constraints,
    estimate_symbolic_region_steps,
)


class SymbolicScopeGate:
    """Scope predicate + step-budget estimate for the experimental symbolic mode."""

    def _supports_symbolic_scope(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
    ) -> tuple[bool, str, dict[str, Any]]:
        """Check whether the current pass is inside the experimental symbolic scope."""
        arch_info = binary.get_arch_info()
        mutations = pass_result.get("mutations", [])
        pass_name = pass_result.get("pass_name", "")
        metadata = build_scope_metadata(mutations, pass_name)
        rejection = check_scope_constraints(arch_info, mutations, pass_name)
        if rejection is not None:
            supported, reason = rejection
            return supported, reason, metadata
        return True, "supported", metadata

    def _estimate_symbolic_region_steps(
        self,
        pass_name: str,
        mutation: dict[str, Any],
    ) -> int:
        """Estimate a small but useful symbolic step budget for a mutated region."""
        return estimate_symbolic_region_steps(pass_name, mutation)
