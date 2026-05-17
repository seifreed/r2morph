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

    def _check_observables(
        self,
        region_report: dict[str, Any],
        mismatches: list[dict[str, Any]],
        mutation: dict[str, Any],
        original_final: Any,
        mutated_final: Any,
        compared_registers: list[str],
        stack_reg: str,
    ) -> None:
        """Compare observables between original and mutated final states."""
        start, end = mutation["start_address"], mutation["end_address"]

        def _record(observable: str) -> None:
            region_report["mismatches"].append(observable)
            mismatches.append({"start_address": start, "end_address": end, "observable": observable})

        # Control flow: exit address
        if getattr(original_final, "addr", None) != getattr(mutated_final, "addr", None):
            _record("successor_address")

        # Registers
        for reg_name in compared_registers:
            if not hasattr(original_final.regs, reg_name) or not hasattr(mutated_final.regs, reg_name):
                continue
            left = getattr(original_final.regs, reg_name)
            right = getattr(mutated_final.regs, reg_name)
            if original_final.solver.satisfiable(extra_constraints=[left != right]):
                _record(reg_name)

        # Flags
        if hasattr(original_final.regs, "eflags") and hasattr(mutated_final.regs, "eflags"):
            if original_final.solver.satisfiable(
                extra_constraints=[original_final.regs.eflags != mutated_final.regs.eflags]
            ):
                _record("eflags")

        # Stack pointer
        original_stack = getattr(original_final.regs, stack_reg)
        mutated_stack = getattr(mutated_final.regs, stack_reg)
        if original_final.solver.satisfiable(extra_constraints=[original_stack != mutated_stack]):
            _record("stack_delta")

        # Memory writes
        original_writes = self._collect_memory_write_signatures(original_final)
        mutated_writes = self._collect_memory_write_signatures(mutated_final)
        region_report["original_memory_writes"] = original_writes
        region_report["mutated_memory_writes"] = mutated_writes
        region_report["original_memory_write_count"] = len(original_writes)
        region_report["mutated_memory_write_count"] = len(mutated_writes)
        if original_writes != mutated_writes:
            _record("memory_writes")

    def _annotate_mutations_with_symbolic_metadata(
        self,
        pass_result: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        """Attach pass-level symbolic evidence to each eligible mutation record."""
        mutations = pass_result.get("mutations", [])
        if not mutations:
            return

        stepped_by_range = {
            (region["start_address"], region["end_address"]): region
            for region in metadata.get("symbolic_stepped_regions", [])
        }
        observable_by_range = {
            (region["start_address"], region["end_address"]): region
            for region in metadata.get("symbolic_observable_regions", [])
        }
        binary_by_range = {
            (region["start_address"], region["end_address"]): region
            for region in metadata.get("symbolic_binary_regions", [])
        }

        for mutation in mutations:
            mutation_metadata = mutation.setdefault("metadata", {})
            mutation_metadata["symbolic_requested"] = bool(metadata.get("symbolic_requested"))
            mutation_metadata["symbolic_status"] = metadata.get("symbolic_status", "unknown")
            mutation_metadata["symbolic_reason"] = metadata.get("symbolic_reason", "")

            key = (mutation["start_address"], mutation["end_address"])
            stepped = stepped_by_range.get(key)
            if stepped is not None:
                mutation_metadata["symbolic_step"] = {
                    "flat_successors": stepped.get("flat_successors", 0),
                    "unsat_successors": stepped.get("unsat_successors", 0),
                    "successor_addresses": list(stepped.get("successor_addresses", [])),
                }

            if pass_result.get("pass_name") == "InstructionSubstitution":
                mutation_metadata["symbolic_semantic_hint"] = metadata.get("symbolic_semantic_hint", "none")
                mutation_metadata["symbolic_semantic_hint_supported"] = bool(
                    metadata.get("symbolic_semantic_hint_supported", False)
                )

                observable = observable_by_range.get(key)
                if observable is not None:
                    mutation_metadata["symbolic_observable_check_performed"] = True
                    mutation_metadata["symbolic_observable_equivalent"] = len(observable.get("mismatches", [])) == 0
                    mutation_metadata["symbolic_observable_mismatches"] = list(observable.get("mismatches", []))
                    mutation_metadata["symbolic_observables_checked"] = list(observable.get("observables_checked", []))
                elif metadata.get("symbolic_observable_check_performed"):
                    mutation_metadata["symbolic_observable_check_performed"] = False
                    mutation_metadata["symbolic_observable_equivalent"] = False
                    mutation_metadata["symbolic_observable_mismatches"] = []

                transition_regions = {
                    (region["start_address"], region["end_address"]): region
                    for region in metadata.get("symbolic_transition_regions", [])
                }
                transition = transition_regions.get(key)
                if transition is not None:
                    mutation_metadata["symbolic_transition_check_performed"] = True
                    mutation_metadata["symbolic_transition_equivalent"] = len(transition.get("mismatches", [])) == 0
                    mutation_metadata["symbolic_transition_mismatches"] = list(transition.get("mismatches", []))
            binary_region = binary_by_range.get(key)
            if binary_region is not None:
                mutation_metadata["symbolic_binary_check_performed"] = True
                mutation_metadata["symbolic_binary_equivalent"] = len(binary_region.get("mismatches", [])) == 0
                mutation_metadata["symbolic_binary_step_budget"] = int(binary_region.get("step_budget", 1))
                mutation_metadata["symbolic_binary_region_exit_budget"] = int(
                    binary_region.get("region_exit_budget", 0)
                )
                mutation_metadata["symbolic_binary_step_strategy"] = binary_region.get(
                    "step_strategy",
                    "unknown",
                )
                mutation_metadata["symbolic_binary_original_region_exit_steps"] = int(
                    binary_region.get("original_region_exit_steps", 0)
                )
                mutation_metadata["symbolic_binary_mutated_region_exit_steps"] = int(
                    binary_region.get("mutated_region_exit_steps", 0)
                )
                mutation_metadata["symbolic_binary_original_region_exit_address"] = binary_region.get(
                    "original_region_exit_address"
                )
                mutation_metadata["symbolic_binary_mutated_region_exit_address"] = binary_region.get(
                    "mutated_region_exit_address"
                )
                mutation_metadata["symbolic_binary_original_trace_addresses"] = list(
                    binary_region.get("original_trace_addresses", [])
                )
                mutation_metadata["symbolic_binary_mutated_trace_addresses"] = list(
                    binary_region.get("mutated_trace_addresses", [])
                )
                mutation_metadata["symbolic_binary_mismatches"] = list(binary_region.get("mismatches", []))
                mutation_metadata["symbolic_binary_registers_checked"] = list(
                    binary_region.get("registers_checked", [])
                )
                mutation_metadata["symbolic_binary_control_flow_observables"] = list(
                    binary_region.get("control_flow_observables", [])
                )
                mutation_metadata["symbolic_binary_original_memory_writes"] = list(
                    binary_region.get("original_memory_writes", [])
                )
                mutation_metadata["symbolic_binary_mutated_memory_writes"] = list(
                    binary_region.get("mutated_memory_writes", [])
                )
                mutation_metadata["symbolic_binary_original_memory_write_count"] = int(
                    binary_region.get("original_memory_write_count", 0)
                )
                mutation_metadata["symbolic_binary_mutated_memory_write_count"] = int(
                    binary_region.get("mutated_memory_write_count", 0)
                )

    def _compare_instruction_substitution_transition(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare successor address and stack delta for supported substitution snippets."""
        arch_info = binary.get_arch_info()
        angr_module = getattr(bridge_module, "angr", None)
        if angr_module is None:
            return {
                "symbolic_transition_check_performed": False,
                "symbolic_transition_reason": "angr module not available",
            }

        arch = arch_info.get("arch")
        bits = arch_info.get("bits")
        if arch in {"x86", "x86_64"} and bits == 64:
            shellcode_arch = "amd64"
            stack_reg = "rsp"
            bit_width = 64
        elif arch == "x86" and bits == 32:
            shellcode_arch = "x86"
            stack_reg = "esp"
            bit_width = 32
        else:
            return {
                "symbolic_transition_check_performed": False,
                "symbolic_transition_reason": "unsupported architecture for transition check",
            }

        options = angr_module.options
        claripy = import_module("claripy")
        compared_regions = []
        mismatches = []

        try:
            for mutation in pass_result.get("mutations", []):
                metadata = mutation.get("metadata", {})
                if not isinstance(metadata.get("equivalence_group_index"), int):
                    continue

                original_project = angr_module.load_shellcode(
                    bytes.fromhex(mutation["original_bytes"]), arch=shellcode_arch
                )
                mutated_project = angr_module.load_shellcode(
                    bytes.fromhex(mutation["mutated_bytes"]), arch=shellcode_arch
                )
                add_options = {
                    options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                }
                original_state = original_project.factory.blank_state(
                    addr=original_project.entry,
                    add_options=add_options,
                )
                mutated_state = mutated_project.factory.blank_state(
                    addr=mutated_project.entry,
                    add_options=add_options,
                )
                shared_stack = claripy.BVV(0x100000, bit_width)
                setattr(original_state.regs, stack_reg, shared_stack)
                setattr(mutated_state.regs, stack_reg, shared_stack)

                original_succ = list(original_project.factory.successors(original_state).flat_successors)
                mutated_succ = list(mutated_project.factory.successors(mutated_state).flat_successors)
                region_report = {
                    "start_address": mutation["start_address"],
                    "end_address": mutation["end_address"],
                    "original_successors": len(original_succ),
                    "mutated_successors": len(mutated_succ),
                    "mismatches": [],
                }

                if len(original_succ) != 1 or len(mutated_succ) != 1:
                    region_report["mismatches"].append("successor_count")
                    mismatches.append(
                        {
                            "start_address": mutation["start_address"],
                            "end_address": mutation["end_address"],
                            "observable": "successor_count",
                        }
                    )
                    compared_regions.append(region_report)
                    continue

                original_final = original_succ[0]
                mutated_final = mutated_succ[0]
                if getattr(original_final, "addr", None) != getattr(mutated_final, "addr", None):
                    region_report["mismatches"].append("successor_address")
                    mismatches.append(
                        {
                            "start_address": mutation["start_address"],
                            "end_address": mutation["end_address"],
                            "observable": "successor_address",
                        }
                    )

                original_stack = getattr(original_final.regs, stack_reg)
                mutated_stack = getattr(mutated_final.regs, stack_reg)
                if original_final.solver.satisfiable(extra_constraints=[original_stack != mutated_stack]):
                    region_report["mismatches"].append("stack_delta")
                    mismatches.append(
                        {
                            "start_address": mutation["start_address"],
                            "end_address": mutation["end_address"],
                            "observable": "stack_delta",
                        }
                    )
                compared_regions.append(region_report)
        except Exception as e:  # angr symbolic execution may raise any exception type
            return {
                "symbolic_transition_check_performed": False,
                "symbolic_transition_reason": f"transition check failed: {e}",
            }

        return {
            "symbolic_transition_check_performed": bool(compared_regions),
            "symbolic_transition_equivalent": not mismatches if compared_regions else False,
            "symbolic_transition_reason": (
                "successor address and stack delta matched"
                if compared_regions and not mismatches
                else (
                    "transition differences detected"
                    if compared_regions
                    else "no eligible instruction substitutions for transition check"
                )
            ),
            "symbolic_transition_regions": compared_regions,
            "symbolic_transition_mismatches": mismatches,
        }
