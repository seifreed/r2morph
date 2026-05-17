"""Shellcode-equivalence checker extracted from SymbolicValidator (slice 2a).

Loads original/mutated instruction bytes as angr shellcode and compares
observable register/flag effects and successor-address/stack transitions
between the two snippets. No real-binary disk access. Imported lazily by
SymbolicValidator.__init__ (composition root).
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from r2morph.core.binary import Binary


class ShellcodeEquivalenceChecker:
    """Bounded angr-shellcode observable/transition equivalence checks."""

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

    def _compare_instruction_substitution_observables(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare a small set of observable register/flag effects for InstructionSubstitution snippets."""
        arch_info = binary.get_arch_info()
        angr_module = getattr(bridge_module, "angr", None)
        if angr_module is None:
            return {
                "symbolic_observable_check_performed": False,
                "symbolic_observable_reason": "angr module not available",
            }

        arch = arch_info.get("arch")
        bits = arch_info.get("bits")
        shellcode_arch = None
        observables: list[str] = []
        if arch in {"x86", "x86_64"} and bits == 64:
            shellcode_arch = "amd64"
            observables = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "eflags"]
        elif arch == "x86" and bits == 32:
            shellcode_arch = "x86"
            observables = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eflags"]
        else:
            return {
                "symbolic_observable_check_performed": False,
                "symbolic_observable_reason": "unsupported architecture for observable check",
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

                original_bytes = bytes.fromhex(mutation["original_bytes"])
                mutated_bytes = bytes.fromhex(mutation["mutated_bytes"])
                original_project = angr_module.load_shellcode(original_bytes, arch=shellcode_arch)
                mutated_project = angr_module.load_shellcode(mutated_bytes, arch=shellcode_arch)
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

                bit_width = 64 if shellcode_arch == "amd64" else 32
                stack_reg = "rsp" if shellcode_arch == "amd64" else "esp"
                base_reg = "rbp" if shellcode_arch == "amd64" else "ebp"
                setattr(original_state.regs, stack_reg, claripy.BVV(0x100000, bit_width))
                setattr(mutated_state.regs, stack_reg, claripy.BVV(0x100000, bit_width))
                setattr(original_state.regs, base_reg, claripy.BVV(0x100000, bit_width))
                setattr(mutated_state.regs, base_reg, claripy.BVV(0x100000, bit_width))

                for reg_name in observables:
                    if reg_name in {stack_reg, base_reg, "eflags"}:
                        continue
                    shared = claripy.BVS(
                        f"{reg_name}_{mutation['start_address']:x}",
                        64 if reg_name.startswith("r") else 32,
                    )
                    if hasattr(original_state.regs, reg_name):
                        setattr(original_state.regs, reg_name, shared)
                    if hasattr(mutated_state.regs, reg_name):
                        setattr(mutated_state.regs, reg_name, shared)

                original_succ = list(original_project.factory.successors(original_state).flat_successors)
                mutated_succ = list(mutated_project.factory.successors(mutated_state).flat_successors)
                region_report = {
                    "start_address": mutation["start_address"],
                    "end_address": mutation["end_address"],
                    "observables_checked": list(observables),
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
                for observable in observables:
                    if not hasattr(original_final.regs, observable) or not hasattr(mutated_final.regs, observable):
                        continue
                    left = getattr(original_final.regs, observable)
                    right = getattr(mutated_final.regs, observable)
                    differs = original_final.solver.satisfiable(extra_constraints=[left != right])
                    if differs:
                        region_report["mismatches"].append(observable)
                        mismatches.append(
                            {
                                "start_address": mutation["start_address"],
                                "end_address": mutation["end_address"],
                                "observable": observable,
                            }
                        )
                compared_regions.append(region_report)
        except Exception as e:  # angr symbolic execution may raise any exception type
            return {
                "symbolic_observable_check_performed": False,
                "symbolic_observable_reason": f"observable check failed: {e}",
            }

        return {
            "symbolic_observable_check_performed": bool(compared_regions),
            "symbolic_observable_equivalent": not mismatches if compared_regions else False,
            "symbolic_observable_reason": (
                "observable register/flag effects matched"
                if compared_regions and not mismatches
                else (
                    "observable register/flag differences detected"
                    if compared_regions
                    else "no eligible instruction substitutions for observable check"
                )
            ),
            "symbolic_observable_regions": compared_regions,
            "symbolic_observable_mismatches": mismatches,
        }
