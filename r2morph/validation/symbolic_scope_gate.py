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
from r2morph.validation.manager import _parse_address


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
        metadata = self._build_scope_metadata(mutations, pass_name)
        rejection = self._check_scope_constraints(arch_info, mutations, pass_name)
        if rejection is not None:
            supported, reason = rejection
            return supported, reason, metadata
        return True, "supported", metadata

    def _build_scope_metadata(
        self,
        mutations: list[dict[str, Any]],
        pass_name: str,
    ) -> dict[str, Any]:
        """Build the symbolic-scope metadata block (independent of the verdict)."""
        return {
            "symbolic_backend": "angr",
            "symbolic_pass_name": pass_name,
            "covered_functions": sorted(
                {
                    _parse_address(mutation["function_address"])
                    for mutation in mutations
                    if mutation.get("function_address") not in (None, 0)
                }
            ),
            "covered_address_ranges": [
                [_parse_address(mutation["start_address"]), _parse_address(mutation["end_address"])]
                for mutation in mutations
            ],
        }

    def _check_scope_constraints(
        self,
        arch_info: dict[str, Any],
        mutations: list[dict[str, Any]],
        pass_name: str,
    ) -> tuple[bool, str] | None:
        """Return the (False, reason) rejection pair, or None when in scope."""
        binary_format = str(arch_info.get("format", ""))
        if not binary_format.startswith("ELF") or arch_info.get("bits") != 64:
            return False, "unsupported-target"
        if arch_info.get("arch") not in {"x86", "x86_64"}:
            return False, "unsupported-target"
        if pass_name not in {"NopInsertion", "InstructionSubstitution", "RegisterSubstitution"}:
            return False, "unsupported-pass"
        if not mutations:
            return False, "no-mutations"
        if len(mutations) > 8:
            return False, "unsupported-scope"
        if any(
            (_parse_address(mutation["end_address"]) - _parse_address(mutation["start_address"]) + 1) > 16
            for mutation in mutations
        ):
            return False, "unsupported-scope"
        if any(mutation.get("function_address") in (None, 0, "0x0") for mutation in mutations):
            return False, "unsupported-scope"
        return None

    def _estimate_symbolic_region_steps(
        self,
        pass_name: str,
        mutation: dict[str, Any],
    ) -> int:
        """Estimate a small but useful symbolic step budget for a mutated region."""
        candidates: list[int] = []
        for key in ("original_disasm", "mutated_disasm"):
            disasm = mutation.get(key)
            if not disasm:
                continue
            if isinstance(disasm, str):
                instructions = [part.strip() for part in disasm.replace("\n", ";").split(";") if part.strip()]
                if instructions:
                    candidates.append(len(instructions))

        region_size = (
            _parse_address(mutation.get("end_address", 0)) - _parse_address(mutation.get("start_address", 0)) + 1
        )
        if region_size > 0:
            candidates.append(1 if region_size <= 4 else 2 if region_size <= 8 else 3)

        step_budget = max(candidates or [1])
        if pass_name == "RegisterSubstitution":
            step_budget = max(step_budget, 2)
        if pass_name == "NopInsertion":
            step_budget = max(step_budget, 2)
        return max(1, min(step_budget, 4))
