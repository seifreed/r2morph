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

    @staticmethod
    def _record_mismatch(
        region_report: dict[str, Any],
        mismatches: list[dict[str, Any]],
        mutation: dict[str, Any],
        observable: str,
    ) -> None:
        """Append an observable mismatch to both the region report and the run list."""
        region_report["mismatches"].append(observable)
        mismatches.append(
            {
                "start_address": mutation["start_address"],
                "end_address": mutation["end_address"],
                "observable": observable,
            }
        )

    @staticmethod
    def _load_shellcode_state_pair(
        angr_module: Any,
        options: Any,
        mutation: dict[str, Any],
        shellcode_arch: str,
    ) -> tuple[Any, Any, Any, Any]:
        """Load original/mutated shellcode and create a blank state for each."""
        original_project = angr_module.load_shellcode(bytes.fromhex(mutation["original_bytes"]), arch=shellcode_arch)
        mutated_project = angr_module.load_shellcode(bytes.fromhex(mutation["mutated_bytes"]), arch=shellcode_arch)
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
        return original_project, original_state, mutated_project, mutated_state

    @staticmethod
    def _transition_arch_config(arch_info: dict[str, Any]) -> tuple[str, str, int] | None:
        """Return (shellcode_arch, stack_reg, bit_width) or None when unsupported."""
        arch = arch_info.get("arch")
        bits = arch_info.get("bits")
        if arch in {"x86", "x86_64"} and bits == 64:
            return "amd64", "rsp", 64
        if arch == "x86" and bits == 32:
            return "x86", "esp", 32
        return None

    def _compare_transition_region(
        self,
        angr_module: Any,
        claripy: Any,
        options: Any,
        mutation: dict[str, Any],
        shellcode_arch: str,
        stack_reg: str,
        bit_width: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Compare successor address + stack delta for one substitution region."""
        original_project, original_state, mutated_project, mutated_state = self._load_shellcode_state_pair(
            angr_module, options, mutation, shellcode_arch
        )
        shared_stack = claripy.BVV(0x100000, bit_width)
        setattr(original_state.regs, stack_reg, shared_stack)
        setattr(mutated_state.regs, stack_reg, shared_stack)

        original_succ = list(original_project.factory.successors(original_state).flat_successors)
        mutated_succ = list(mutated_project.factory.successors(mutated_state).flat_successors)
        region_report: dict[str, Any] = {
            "start_address": mutation["start_address"],
            "end_address": mutation["end_address"],
            "original_successors": len(original_succ),
            "mutated_successors": len(mutated_succ),
            "mismatches": [],
        }
        region_mismatches: list[dict[str, Any]] = []

        if len(original_succ) != 1 or len(mutated_succ) != 1:
            self._record_mismatch(region_report, region_mismatches, mutation, "successor_count")
            return region_report, region_mismatches

        original_final = original_succ[0]
        mutated_final = mutated_succ[0]
        if getattr(original_final, "addr", None) != getattr(mutated_final, "addr", None):
            self._record_mismatch(region_report, region_mismatches, mutation, "successor_address")

        original_stack = getattr(original_final.regs, stack_reg)
        mutated_stack = getattr(mutated_final.regs, stack_reg)
        if original_final.solver.satisfiable(extra_constraints=[original_stack != mutated_stack]):
            self._record_mismatch(region_report, region_mismatches, mutation, "stack_delta")
        return region_report, region_mismatches

    def _compare_instruction_substitution_transition(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare successor address and stack delta for supported substitution snippets."""
        angr_module = getattr(bridge_module, "angr", None)
        if angr_module is None:
            return {
                "symbolic_transition_check_performed": False,
                "symbolic_transition_reason": "angr module not available",
            }

        config = self._transition_arch_config(binary.get_arch_info())
        if config is None:
            return {
                "symbolic_transition_check_performed": False,
                "symbolic_transition_reason": "unsupported architecture for transition check",
            }
        shellcode_arch, stack_reg, bit_width = config

        options = angr_module.options
        claripy = import_module("claripy")
        compared_regions: list[dict[str, Any]] = []
        mismatches: list[dict[str, Any]] = []

        try:
            for mutation in pass_result.get("mutations", []):
                metadata = mutation.get("metadata", {})
                if not isinstance(metadata.get("equivalence_group_index"), int):
                    continue
                region_report, region_mismatches = self._compare_transition_region(
                    angr_module, claripy, options, mutation, shellcode_arch, stack_reg, bit_width
                )
                compared_regions.append(region_report)
                mismatches.extend(region_mismatches)
        except Exception as e:  # angr symbolic execution may raise any exception type
            return {
                "symbolic_transition_check_performed": False,
                "symbolic_transition_reason": f"transition check failed: {e}",
            }

        return self._build_transition_result(compared_regions, mismatches)

    @staticmethod
    def _build_transition_result(
        compared_regions: list[dict[str, Any]],
        mismatches: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Assemble the transition-check result dict from the per-region outcomes."""
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

    @staticmethod
    def _observables_arch_config(arch_info: dict[str, Any]) -> tuple[str, list[str]] | None:
        """Return (shellcode_arch, observables) or None when unsupported."""
        arch = arch_info.get("arch")
        bits = arch_info.get("bits")
        if arch in {"x86", "x86_64"} and bits == 64:
            return "amd64", ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "eflags"]
        if arch == "x86" and bits == 32:
            return "x86", ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eflags"]
        return None

    @staticmethod
    def _seed_observable_registers(
        claripy: Any,
        original_state: Any,
        mutated_state: Any,
        mutation: dict[str, Any],
        shellcode_arch: str,
        observables: list[str],
    ) -> None:
        """Pin the stack/base pointers and share symbolic values for the tracked registers."""
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

    def _compare_observable_region(
        self,
        angr_module: Any,
        claripy: Any,
        options: Any,
        mutation: dict[str, Any],
        shellcode_arch: str,
        observables: list[str],
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Compare observable register/flag effects for one substitution region."""
        original_project, original_state, mutated_project, mutated_state = self._load_shellcode_state_pair(
            angr_module, options, mutation, shellcode_arch
        )
        self._seed_observable_registers(claripy, original_state, mutated_state, mutation, shellcode_arch, observables)

        original_succ = list(original_project.factory.successors(original_state).flat_successors)
        mutated_succ = list(mutated_project.factory.successors(mutated_state).flat_successors)
        region_report: dict[str, Any] = {
            "start_address": mutation["start_address"],
            "end_address": mutation["end_address"],
            "observables_checked": list(observables),
            "original_successors": len(original_succ),
            "mutated_successors": len(mutated_succ),
            "mismatches": [],
        }
        region_mismatches: list[dict[str, Any]] = []

        if len(original_succ) != 1 or len(mutated_succ) != 1:
            self._record_mismatch(region_report, region_mismatches, mutation, "successor_count")
            return region_report, region_mismatches

        original_final = original_succ[0]
        mutated_final = mutated_succ[0]
        for observable in observables:
            if not hasattr(original_final.regs, observable) or not hasattr(mutated_final.regs, observable):
                continue
            left = getattr(original_final.regs, observable)
            right = getattr(mutated_final.regs, observable)
            if original_final.solver.satisfiable(extra_constraints=[left != right]):
                self._record_mismatch(region_report, region_mismatches, mutation, observable)
        return region_report, region_mismatches

    def _compare_instruction_substitution_observables(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare a small set of observable register/flag effects for InstructionSubstitution snippets."""
        angr_module = getattr(bridge_module, "angr", None)
        if angr_module is None:
            return {
                "symbolic_observable_check_performed": False,
                "symbolic_observable_reason": "angr module not available",
            }

        config = self._observables_arch_config(binary.get_arch_info())
        if config is None:
            return {
                "symbolic_observable_check_performed": False,
                "symbolic_observable_reason": "unsupported architecture for observable check",
            }
        shellcode_arch, observables = config

        options = angr_module.options
        claripy = import_module("claripy")
        compared_regions: list[dict[str, Any]] = []
        mismatches: list[dict[str, Any]] = []

        try:
            for mutation in pass_result.get("mutations", []):
                metadata = mutation.get("metadata", {})
                if not isinstance(metadata.get("equivalence_group_index"), int):
                    continue
                region_report, region_mismatches = self._compare_observable_region(
                    angr_module, claripy, options, mutation, shellcode_arch, observables
                )
                compared_regions.append(region_report)
                mismatches.extend(region_mismatches)
        except Exception as e:  # angr symbolic execution may raise any exception type
            return {
                "symbolic_observable_check_performed": False,
                "symbolic_observable_reason": f"observable check failed: {e}",
            }

        return self._build_observable_result(compared_regions, mismatches)

    @staticmethod
    def _build_observable_result(
        compared_regions: list[dict[str, Any]],
        mismatches: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Assemble the observable-check result dict from the per-region outcomes."""
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
