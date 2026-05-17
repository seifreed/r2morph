"""Symbolic-validation collaborator extracted from ValidationManager.

Slice 6a: the shell plus the small stateless helpers. The remaining
symbolic methods are moved here in slice 7. Imported lazily by
ValidationManager.__init__ (composition root) so the dependency on
r2morph.validation.manager (_parse_address, and later
ValidationIssue/ValidationOutcome) is not a circular import.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.manager import _parse_address


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

    def _compare_real_binary_regions(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare bounded symbolic effects on the real pre-pass and post-pass binaries."""
        return self._binary_comparator._compare_real_binary_regions(binary, pass_result, bridge_module)

    def _run_symbolic_precheck(self, binary: Binary, pass_result: dict[str, Any]) -> dict[str, Any]:
        """Run a bounded symbolic precheck for the experimental mode."""
        supported, reason, metadata = self._scope_gate._supports_symbolic_scope(binary, pass_result)
        payload = {
            "symbolic_requested": True,
            "symbolic_proven": False,
            **metadata,
        }

        if not supported:
            payload["symbolic_status"] = reason
            payload["symbolic_reason"] = "falling back to structural validation"
            return payload

        try:
            bridge_module = import_module("r2morph.analysis.symbolic.angr_bridge")
            if not getattr(bridge_module, "ANGR_AVAILABLE", False):
                payload["symbolic_status"] = "backend-unavailable"
                payload["symbolic_reason"] = "angr is not installed"
                return payload

            bridge = bridge_module.AngrBridge(binary)
            initialized = []
            stepped_regions = []
            total_flat_successors = 0
            total_unsat_successors = 0
            step_error: str | None = None

            for mutation in pass_result.get("mutations", []):
                start = _parse_address(mutation["start_address"])
                end = _parse_address(mutation["end_address"])
                state = bridge.create_symbolic_state(start)
                if state is None:
                    step_error = f"failed to initialize symbolic state at 0x{start:x}"
                    break

                initialized.append([start, end])
                step_budget = self._scope_gate._estimate_symbolic_region_steps(
                    pass_result.get("pass_name", ""),
                    mutation,
                )

                try:
                    successors = bridge.angr_project.factory.successors(
                        state,
                        num_inst=step_budget,
                    )
                except Exception as e:  # angr may raise any exception type during symbolic execution
                    step_error = f"bounded symbolic step failed at 0x{start:x}: {e}"
                    break

                flat_successors = list(getattr(successors, "flat_successors", []))
                unsat_successors = list(getattr(successors, "unsat_successors", []))
                successor_addrs = sorted(
                    {succ.addr for succ in flat_successors if getattr(succ, "addr", None) is not None}
                )
                total_flat_successors += len(flat_successors)
                total_unsat_successors += len(unsat_successors)
                stepped_regions.append(
                    {
                        "start_address": start,
                        "end_address": end,
                        "flat_successors": len(flat_successors),
                        "unsat_successors": len(unsat_successors),
                        "successor_addresses": successor_addrs,
                        "step_budget": step_budget,
                    }
                )

            payload["symbolic_status"] = "bounded-step-passed"
            payload["symbolic_reason"] = (
                "symbolic backend initialized and executed one bounded step per mutation region"
            )
            payload["symbolic_initialized_regions"] = initialized
            payload["symbolic_step_count"] = len(stepped_regions)
            payload["symbolic_flat_successors"] = total_flat_successors
            payload["symbolic_unsat_successors"] = total_unsat_successors
            payload["symbolic_stepped_regions"] = stepped_regions
            payload.update(self._build_instruction_substitution_symbolic_hint(pass_result))
            if step_error is not None:
                payload["symbolic_status"] = (
                    "state-init-failed" if step_error.startswith("failed to initialize") else "step-failed"
                )
                payload["symbolic_reason"] = step_error
                if payload.get("symbolic_semantic_hint_supported"):
                    payload.update(
                        self._shellcode_checker._compare_instruction_substitution_observables(
                            binary, pass_result, bridge_module
                        )
                    )
                    payload.update(
                        self._shellcode_checker._compare_instruction_substitution_transition(
                            binary, pass_result, bridge_module
                        )
                    )
                    if payload.get("symbolic_observable_check_performed"):
                        transition_ok = payload.get("symbolic_transition_equivalent", True)
                        if payload.get("symbolic_observable_equivalent") and transition_ok:
                            payload["symbolic_status"] = "shellcode-observables-match"
                            payload["symbolic_reason"] = (
                                "binary symbolic step failed but shellcode observable/transition checks matched"
                            )
                        else:
                            payload["symbolic_status"] = "shellcode-observable-mismatch"
                            payload["symbolic_reason"] = (
                                "binary symbolic step failed and shellcode observable or transition checks diverged"
                            )
                return payload
            if payload.get("symbolic_semantic_hint_supported"):
                payload["symbolic_status"] = "bounded-step-known-equivalence"
                payload["symbolic_reason"] = (
                    "symbolic bounded step passed and substitutions map to a known equivalence group"
                )
                payload.update(
                    self._shellcode_checker._compare_instruction_substitution_observables(
                        binary, pass_result, bridge_module
                    )
                )
                payload.update(
                    self._shellcode_checker._compare_instruction_substitution_transition(
                        binary, pass_result, bridge_module
                    )
                )
                if payload.get("symbolic_observable_check_performed"):
                    transition_ok = payload.get("symbolic_transition_equivalent", True)
                    if payload.get("symbolic_observable_equivalent") and transition_ok:
                        payload["symbolic_status"] = "bounded-step-observables-match"
                        payload["symbolic_reason"] = (
                            "bounded symbolic step passed and observable/transition effects matched"
                        )
                    else:
                        payload["symbolic_status"] = "bounded-step-observable-mismatch"
                        payload["symbolic_reason"] = (
                            "bounded symbolic step passed but observable or transition effects diverged"
                        )
            return payload
        except Exception as e:  # angr/claripy backend may raise any exception type
            payload["symbolic_status"] = "backend-error"
            payload["symbolic_reason"] = str(e)
            return payload
