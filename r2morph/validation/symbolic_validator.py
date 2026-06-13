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


class SymbolicValidator:
    """Bounded symbolic-equivalence checks for a pass, composed of
    extracted collaborators (clean-arch decomposition)."""

    def __init__(self) -> None:
        from r2morph.validation.binary_region_comparator import BinaryRegionComparator
        from r2morph.validation.mutation_annotator import MutationAnnotator
        from r2morph.validation.shellcode_equivalence import ShellcodeEquivalenceChecker
        from r2morph.validation.symbolic_scope_gate import SymbolicScopeGate

        self._scope_gate = SymbolicScopeGate()
        self._mutation_annotator = MutationAnnotator()
        self._shellcode_checker = ShellcodeEquivalenceChecker()
        self._binary_comparator = BinaryRegionComparator()

    def _build_instruction_substitution_symbolic_hint(self, pass_result: dict[str, Any]) -> dict[str, Any]:
        """Add a narrow semantic hint for instruction substitutions from known equivalence groups."""
        if pass_result.get("pass_name") != "InstructionSubstitution":
            return {}

        mutations = pass_result.get("mutations", [])
        if not mutations:
            return {}

        supported, unsupported = self._classify_substitution_regions(mutations)
        return self._assemble_substitution_hint(supported, unsupported)

    @staticmethod
    def _classify_substitution_regions(
        mutations: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Partition substitution mutations into known-equivalence vs unsupported regions."""
        supported: list[dict[str, Any]] = []
        unsupported: list[dict[str, Any]] = []
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
        return supported, unsupported

    @staticmethod
    def _assemble_substitution_hint(
        supported: list[dict[str, Any]],
        unsupported: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build the semantic-hint payload from the classified substitution regions."""
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

    def _run_symbolic_precheck(self, binary: Binary, pass_result: dict[str, Any]) -> dict[str, Any]:
        """Run a bounded symbolic precheck for the experimental mode."""
        from r2morph.validation.symbolic_precheck_flow import run_symbolic_precheck

        return run_symbolic_precheck(
            binary,
            pass_result,
            supports_scope=self._scope_gate._supports_symbolic_scope,
            estimate_steps=self._scope_gate._estimate_symbolic_region_steps,
            build_hint=self._build_instruction_substitution_symbolic_hint,
            compare_observables=self._shellcode_checker._compare_instruction_substitution_observables,
            compare_transition=self._shellcode_checker._compare_instruction_substitution_transition,
        )
