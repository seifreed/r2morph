"""Symbolic-validation collaborator extracted from ValidationManager.

Slice 6a: the shell plus the small stateless helpers. The remaining
symbolic methods are moved here in slice 7. Imported lazily by
ValidationManager.__init__ (composition root) so the dependency on
r2morph.validation.manager (_parse_address, and later
ValidationIssue/ValidationOutcome) is not a circular import.
"""

from __future__ import annotations

from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.manager import _parse_address


class SymbolicValidator:
    """Bounded symbolic-equivalence checks for a pass (no stored state)."""

    def _collect_memory_write_signatures(self, state: Any) -> list[str]:
        """Collect a compact, best-effort signature of memory writes from an angr state."""
        signatures: list[str] = []
        history = getattr(state, "history", None)
        actions = getattr(history, "actions", None)
        if not actions:
            return signatures
        for action in actions:
            action_type = getattr(action, "type", "")
            action_action = getattr(action, "action", "")
            if action_type != "mem" or action_action not in {"write", "store"}:
                continue
            addr = getattr(action, "addr", None)
            size = getattr(action, "size", None)
            try:
                raw_addr = getattr(addr, "concrete_value", addr)
                addr_value = int(raw_addr) if raw_addr is not None else None
            except (TypeError, ValueError):
                addr_value = None
            try:
                raw_size = getattr(size, "concrete_value", size)
                size_value = int(raw_size) if raw_size is not None else None
            except (TypeError, ValueError):
                size_value = None
            if addr_value is None:
                signatures.append("unknown")
            elif size_value is None:
                signatures.append(f"0x{addr_value:x}")
            else:
                signatures.append(f"0x{addr_value:x}:{size_value}")
        return sorted(set(signatures))

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

    def _supports_symbolic_scope(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
    ) -> tuple[bool, str, dict[str, Any]]:
        """Check whether the current pass is inside the experimental symbolic scope."""
        arch_info = binary.get_arch_info()
        mutations = pass_result.get("mutations", [])
        pass_name = pass_result.get("pass_name", "")

        metadata = {
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

        binary_format = str(arch_info.get("format", ""))
        if not binary_format.startswith("ELF") or arch_info.get("bits") != 64:
            return False, "unsupported-target", metadata
        if arch_info.get("arch") not in {"x86", "x86_64"}:
            return False, "unsupported-target", metadata
        if pass_name not in {"NopInsertion", "InstructionSubstitution", "RegisterSubstitution"}:
            return False, "unsupported-pass", metadata
        if not mutations:
            return False, "no-mutations", metadata
        if len(mutations) > 8:
            return False, "unsupported-scope", metadata
        if any(
            (_parse_address(mutation["end_address"]) - _parse_address(mutation["start_address"]) + 1) > 16
            for mutation in mutations
        ):
            return False, "unsupported-scope", metadata
        if any(mutation.get("function_address") in (None, 0, "0x0") for mutation in mutations):
            return False, "unsupported-scope", metadata
        return True, "supported", metadata

    def _build_instruction_substitution_symbolic_hint(self, pass_result: dict[str, Any]) -> dict[str, Any]:
        """Add a narrow semantic hint for instruction substitutions from known equivalence groups."""
        if pass_result.get("pass_name") != "InstructionSubstitution":
            return {}

        mutations = pass_result.get("mutations", [])
        if not mutations:
            return {}

        supported = []
        unsupported = []
        for mutation in mutations:
            metadata = mutation.get("metadata", {})
            members = metadata.get("equivalence_members") or []
            original = metadata.get("equivalence_original_pattern")
            replacement = metadata.get("equivalence_replacement_pattern")
            group_index = metadata.get("equivalence_group_index")
            if isinstance(group_index, int) and original in members and replacement in members and len(members) >= 2:
                supported.append(
                    {
                        "start_address": mutation["start_address"],
                        "end_address": mutation["end_address"],
                        "equivalence_group_index": group_index,
                        "equivalence_group_size": len(members),
                    }
                )
            else:
                unsupported.append(
                    {
                        "start_address": mutation["start_address"],
                        "end_address": mutation["end_address"],
                    }
                )

        if not supported:
            return {
                "symbolic_semantic_hint": "no-known-equivalence-group",
                "symbolic_semantic_hint_supported": False,
            }

        hint = {
            "symbolic_semantic_hint": "known-equivalence-group",
            "symbolic_semantic_hint_supported": True,
            "symbolic_semantic_hint_regions": supported,
        }
        if unsupported:
            hint["symbolic_semantic_hint_partial"] = True
            hint["symbolic_semantic_hint_unsupported_regions"] = unsupported
        else:
            hint["symbolic_semantic_hint_partial"] = False

        return hint
