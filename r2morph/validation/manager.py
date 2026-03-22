"""
Validation management for mutation passes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from dataclasses import asdict, dataclass, field
from importlib import import_module
from typing import Any

from r2morph.analysis.abi_checker import ABIChecker
from r2morph.analysis.invariants import InvariantDetector
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


def _parse_address(value: int | str | None) -> int:
    """Parse an address that may be an int or hex string like '0x401010'."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.startswith("0x"):
        return int(value, 16)
    return int(value)


@dataclass
class ValidationIssue:
    """Represents a validation failure or warning."""

    validator: str
    message: str
    address_range: tuple[int, int] | None = None
    severity: str = "error"
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        payload = asdict(self)
        if self.address_range is not None:
            payload["address_range"] = [self.address_range[0], self.address_range[1]]
        return payload


@dataclass
class ValidationOutcome:
    """Result of a validation run."""

    validator_type: str
    passed: bool
    scope: str
    issues: list[ValidationIssue] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        return {
            "validator_type": self.validator_type,
            "passed": self.passed,
            "scope": self.scope,
            "issues": [issue.to_dict() for issue in self.issues],
            "metadata": dict(self.metadata),
        }


class ValidationManager:
    """
    Coordinates structural validation for mutations and passes.
    """

    def __init__(self, mode: str = "structural", check_abi: bool = False):
        self.mode = mode
        self.check_abi = check_abi
        self._abi_checker: ABIChecker | None = None

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
                addr_value = int(getattr(addr, "concrete_value", addr))
            except Exception:
                addr_value = None
            try:
                size_value = int(getattr(size, "concrete_value", size))
            except Exception:
                size_value = None
            if addr_value is None:
                signatures.append("unknown")
            elif size_value is None:
                signatures.append(f"0x{addr_value:x}")
            else:
                signatures.append(f"0x{addr_value:x}:{size_value}")
        return sorted(set(signatures))

    def _validate_structural_mutation(
        self,
        binary: Binary,
        mutation: dict[str, Any],
        *,
        validator_type: str,
    ) -> ValidationOutcome:
        """Validate a single mutation using structural checks."""
        issues: list[ValidationIssue] = []
        start = mutation["start_address"]
        end = mutation["end_address"]
        expected_bytes = bytes.fromhex(mutation["mutated_bytes"])
        readback = binary.read_bytes(start, len(expected_bytes))

        if readback != expected_bytes:
            issues.append(
                ValidationIssue(
                    validator="patch_integrity",
                    message="Mutated bytes do not match readback from binary",
                    address_range=(start, end),
                    evidence={
                        "expected": mutation["mutated_bytes"],
                        "actual": readback.hex(),
                    },
                )
            )

        function_address = mutation.get("function_address")
        baseline = mutation.get("metadata", {}).get("structural_baseline", {})
        if function_address not in (None, 0):
            detector = InvariantDetector(binary)
            expected = baseline.get("invariants", [])
            try:
                current = detector.detect_all_invariants(function_address)
            except Exception as e:
                issues.append(
                    ValidationIssue(
                        validator="structural",
                        message="Failed to analyze mutated function",
                        address_range=(start, end),
                        evidence={"error": str(e), "function_address": function_address},
                    )
                )
                current = []

            if expected:
                current_keys = {(inv.invariant_type.value, inv.location) for inv in current}
                missing = [inv for inv in expected if (inv["type"], inv["location"]) not in current_keys]
                if missing:
                    issues.append(
                        ValidationIssue(
                            validator="invariants",
                            message="Mutation invalidated previously observed invariants",
                            address_range=(start, end),
                            evidence={"missing_invariants": missing},
                        )
                    )

            try:
                binary.get_function_disasm(function_address)
                binary.get_basic_blocks(function_address)
            except Exception as e:
                issues.append(
                    ValidationIssue(
                        validator="control_flow",
                        message="Failed to recover function control-flow after mutation",
                        address_range=(start, end),
                        evidence={"error": str(e), "function_address": function_address},
                    )
                )

        return ValidationOutcome(
            validator_type=validator_type,
            passed=not issues,
            scope="mutation",
            issues=issues,
            metadata={"pass_name": mutation.get("pass_name")},
        )

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

    def _run_symbolic_precheck(self, binary: Binary, pass_result: dict[str, Any]) -> dict[str, Any]:
        """Run a bounded symbolic precheck for the experimental mode."""
        supported, reason, metadata = self._supports_symbolic_scope(binary, pass_result)
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
                step_budget = self._estimate_symbolic_region_steps(
                    pass_result.get("pass_name", ""),
                    mutation,
                )

                try:
                    successors = bridge.angr_project.factory.successors(
                        state,
                        num_inst=step_budget,
                    )
                except Exception as e:
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
                        self._compare_instruction_substitution_observables(binary, pass_result, bridge_module)
                    )
                    payload.update(
                        self._compare_instruction_substitution_transition(binary, pass_result, bridge_module)
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
                payload.update(self._compare_instruction_substitution_observables(binary, pass_result, bridge_module))
                payload.update(self._compare_instruction_substitution_transition(binary, pass_result, bridge_module))
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
        except Exception as e:
            payload["symbolic_status"] = "backend-error"
            payload["symbolic_reason"] = str(e)
            return payload

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
        except Exception as e:
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
                else "observable register/flag differences detected"
                if compared_regions
                else "no eligible instruction substitutions for observable check"
            ),
            "symbolic_observable_regions": compared_regions,
            "symbolic_observable_mismatches": mismatches,
        }

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
        except Exception as e:
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
                else "transition differences detected"
                if compared_regions
                else "no eligible instruction substitutions for transition check"
            ),
            "symbolic_transition_regions": compared_regions,
            "symbolic_transition_mismatches": mismatches,
        }

    def _compare_real_binary_regions(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare bounded symbolic effects on the real pre-pass and post-pass binaries."""
        previous_binary_path = pass_result.get("previous_binary_path")
        if not previous_binary_path:
            return {
                "symbolic_binary_check_performed": False,
                "symbolic_binary_reason": "no previous binary checkpoint available",
            }

        current_binary_path = getattr(binary, "path", None)
        if not current_binary_path:
            return {
                "symbolic_binary_check_performed": False,
                "symbolic_binary_reason": "current binary path not available",
            }

        previous_binary_path = Path(previous_binary_path)
        current_binary_path = Path(current_binary_path)
        if not previous_binary_path.exists() or not current_binary_path.exists():
            return {
                "symbolic_binary_check_performed": False,
                "symbolic_binary_reason": "real binary artifacts not available on disk",
            }

        original_bridge = None
        mutated_bridge = None
        try:
            from r2morph.analysis.symbolic.angr_bridge import AngrBridge

            with Binary(previous_binary_path, writable=False) as original_binary:
                try:
                    original_binary.analyze("aa")
                except Exception as analyze_error:
                    logger.warning(f"Failed to analyze original binary: {analyze_error}")
                    return {
                        "symbolic_binary_check_performed": False,
                        "symbolic_binary_reason": f"Failed to analyze original binary: {analyze_error}",
                    }
                try:
                    original_bridge = AngrBridge(original_binary)
                except Exception as bridge_error:
                    logger.error(f"Failed to create original bridge: {bridge_error}")
                    return {
                        "symbolic_binary_check_performed": False,
                        "symbolic_binary_reason": f"Failed to create original bridge: {bridge_error}",
                    }
                try:
                    mutated_bridge = AngrBridge(binary)
                except Exception as bridge_error:
                    if original_bridge and hasattr(original_bridge, "angr_project"):
                        try:
                            original_bridge.angr_project.loader.close()
                        except Exception:
                            pass
                    logger.error(f"Failed to create mutated bridge: {bridge_error}")
                    return {
                        "symbolic_binary_check_performed": False,
                        "symbolic_binary_reason": f"Failed to create mutated bridge: {bridge_error}",
                    }
                angr_module = getattr(bridge_module, "angr", None)
                if angr_module is None:
                    return {
                        "symbolic_binary_check_performed": False,
                        "symbolic_binary_reason": "angr module not available",
                    }
                claripy = import_module("claripy")
                options = angr_module.options
                compared_regions = []
                mismatches = []
                for mutation in pass_result.get("mutations", []):
                    start = mutation["start_address"]
                    end = mutation["end_address"]
                    step_budget = self._estimate_symbolic_region_steps(
                        pass_result.get("pass_name", ""),
                        mutation,
                    )
                    region_width = max(1, end - start + 1)
                    region_exit_budget = max(step_budget * 2, region_width + 1)
                    resolved_original = original_bridge.resolve_loaded_address(start)
                    resolved_mutated = mutated_bridge.resolve_loaded_address(start)
                    if resolved_original is None or resolved_mutated is None:
                        logger.warning(f"Failed to resolve loaded address for mutation at 0x{start:x}")
                        continue

                    original_state = original_bridge.angr_project.factory.blank_state(
                        addr=resolved_original,
                        add_options={
                            options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                            options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                        },
                    )
                    mutated_state = mutated_bridge.angr_project.factory.blank_state(
                        addr=resolved_mutated,
                        add_options={
                            options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                            options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                        },
                    )
                    bit_width = 64 if original_binary.get_arch_info().get("bits") == 64 else 32
                    stack_reg = "rsp" if bit_width == 64 else "esp"
                    base_reg = "rbp" if bit_width == 64 else "ebp"
                    setattr(original_state.regs, stack_reg, claripy.BVV(0x100000, bit_width))
                    setattr(mutated_state.regs, stack_reg, claripy.BVV(0x100000, bit_width))
                    setattr(original_state.regs, base_reg, claripy.BVV(0x100000, bit_width))
                    setattr(mutated_state.regs, base_reg, claripy.BVV(0x100000, bit_width))

                    compared_registers = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"]
                    if bit_width == 32:
                        compared_registers = ["eax", "ebx", "ecx", "edx", "esi", "edi"]
                    for reg_name in compared_registers:
                        shared = claripy.BVS(f"{reg_name}_{start:x}", bit_width)
                        if hasattr(original_state.regs, reg_name):
                            setattr(original_state.regs, reg_name, shared)
                        if hasattr(mutated_state.regs, reg_name):
                            setattr(mutated_state.regs, reg_name, shared)

                    step_strategy = "region-exit"
                    original_final = original_state
                    mutated_final = mutated_state
                    original_steps = 0
                    mutated_steps = 0
                    original_exit_error = None
                    mutated_exit_error = None
                    original_trace_addresses = [resolved_original]
                    mutated_trace_addresses = [resolved_mutated]
                    for _ in range(region_exit_budget):
                        current_original_addr = getattr(original_final, "addr", None)
                        if (
                            current_original_addr is None
                            or current_original_addr > resolved_original + region_width - 1
                        ):
                            break
                        original_succ = list(
                            original_bridge.angr_project.factory.successors(
                                original_final,
                                num_inst=1,
                            ).flat_successors
                        )
                        if len(original_succ) != 1:
                            original_exit_error = "successor_count"
                            break
                        original_final = original_succ[0]
                        original_steps += 1
                        next_original_addr = getattr(original_final, "addr", None)
                        if next_original_addr is not None:
                            original_trace_addresses.append(next_original_addr)
                    else:
                        original_exit_error = "region_exit_budget_exhausted"

                    for _ in range(region_exit_budget):
                        current_mutated_addr = getattr(mutated_final, "addr", None)
                        if current_mutated_addr is None or current_mutated_addr > resolved_mutated + region_width - 1:
                            break
                        mutated_succ = list(
                            mutated_bridge.angr_project.factory.successors(
                                mutated_final,
                                num_inst=1,
                            ).flat_successors
                        )
                        if len(mutated_succ) != 1:
                            mutated_exit_error = "successor_count"
                            break
                        mutated_final = mutated_succ[0]
                        mutated_steps += 1
                        next_mutated_addr = getattr(mutated_final, "addr", None)
                        if next_mutated_addr is not None:
                            mutated_trace_addresses.append(next_mutated_addr)
                    else:
                        mutated_exit_error = "region_exit_budget_exhausted"

                    region_report = {
                        "start_address": mutation["start_address"],
                        "end_address": mutation["end_address"],
                        "original_loaded_address": resolved_original,
                        "mutated_loaded_address": resolved_mutated,
                        "step_budget": step_budget,
                        "region_exit_budget": region_exit_budget,
                        "step_strategy": step_strategy,
                        "original_region_exit_steps": original_steps,
                        "mutated_region_exit_steps": mutated_steps,
                        "original_trace_addresses": original_trace_addresses,
                        "mutated_trace_addresses": mutated_trace_addresses,
                        "registers_checked": list(compared_registers) + ["eflags", "stack_delta"],
                        "mismatches": [],
                    }
                    if original_exit_error or mutated_exit_error:
                        step_strategy = "region-exit-fallback-budget"
                        region_report["step_strategy"] = step_strategy
                        exit_error = original_exit_error or mutated_exit_error
                        if original_exit_error and mutated_exit_error and original_exit_error != mutated_exit_error:
                            exit_error = f"{original_exit_error}|{mutated_exit_error}"
                        region_report["mismatches"].append(exit_error)
                        mismatches.append(
                            {
                                "start_address": mutation["start_address"],
                                "end_address": mutation["end_address"],
                                "observable": exit_error,
                            }
                        )
                        compared_regions.append(region_report)
                        continue

                    region_report["original_region_exit_address"] = getattr(original_final, "addr", None)
                    region_report["mutated_region_exit_address"] = getattr(mutated_final, "addr", None)
                    region_report["control_flow_observables"] = [
                        "region_exit_address",
                        "region_exit_steps",
                    ]
                    if getattr(original_final, "addr", None) != getattr(mutated_final, "addr", None):
                        region_report["mismatches"].append("successor_address")
                        mismatches.append(
                            {
                                "start_address": mutation["start_address"],
                                "end_address": mutation["end_address"],
                                "observable": "successor_address",
                            }
                        )

                    for reg_name in compared_registers:
                        if not hasattr(original_final.regs, reg_name) or not hasattr(mutated_final.regs, reg_name):
                            continue
                        left = getattr(original_final.regs, reg_name)
                        right = getattr(mutated_final.regs, reg_name)
                        if original_final.solver.satisfiable(extra_constraints=[left != right]):
                            region_report["mismatches"].append(reg_name)
                            mismatches.append(
                                {
                                    "start_address": mutation["start_address"],
                                    "end_address": mutation["end_address"],
                                    "observable": reg_name,
                                }
                            )
                    if hasattr(original_final.regs, "eflags") and hasattr(mutated_final.regs, "eflags"):
                        if original_final.solver.satisfiable(
                            extra_constraints=[original_final.regs.eflags != mutated_final.regs.eflags]
                        ):
                            region_report["mismatches"].append("eflags")
                            mismatches.append(
                                {
                                    "start_address": mutation["start_address"],
                                    "end_address": mutation["end_address"],
                                    "observable": "eflags",
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
                    original_writes = self._collect_memory_write_signatures(original_final)
                    mutated_writes = self._collect_memory_write_signatures(mutated_final)
                    region_report["original_memory_writes"] = original_writes
                    region_report["mutated_memory_writes"] = mutated_writes
                    region_report["original_memory_write_count"] = len(original_writes)
                    region_report["mutated_memory_write_count"] = len(mutated_writes)
                    if original_writes != mutated_writes:
                        region_report["mismatches"].append("memory_writes")
                        mismatches.append(
                            {
                                "start_address": mutation["start_address"],
                                "end_address": mutation["end_address"],
                                "observable": "memory_writes",
                            }
                        )
                    compared_regions.append(region_report)
        except Exception as e:
            return {
                "symbolic_binary_check_performed": False,
                "symbolic_binary_reason": f"real binary symbolic comparison failed: {e}",
            }
        finally:
            cleanup_errors = []
            if original_bridge is not None and hasattr(original_bridge, "angr_project"):
                try:
                    if hasattr(original_bridge.angr_project, "loader"):
                        original_bridge.angr_project.loader.close()
                except Exception as e:
                    cleanup_errors.append(f"original: {e}")
                    logger.warning(f"Error closing original angr project: {e}")
            if mutated_bridge is not None and hasattr(mutated_bridge, "angr_project"):
                try:
                    if hasattr(mutated_bridge.angr_project, "loader"):
                        mutated_bridge.angr_project.loader.close()
                except Exception as e:
                    cleanup_errors.append(f"mutated: {e}")
                    logger.warning(f"Error closing mutated angr project: {e}")
            if cleanup_errors:
                logger.debug(f"Cleanup errors during angr resource release: {cleanup_errors}")

        return {
            "symbolic_binary_check_performed": bool(compared_regions),
            "symbolic_binary_equivalent": not mismatches if compared_regions else False,
            "symbolic_binary_reason": (
                "bounded real-binary symbolic effects matched"
                if compared_regions and not mismatches
                else "bounded real-binary symbolic effects diverged"
                if compared_regions
                else "no eligible regions for real-binary symbolic comparison"
            ),
            "symbolic_binary_regions": compared_regions,
            "symbolic_binary_mismatches": mismatches,
            "symbolic_binary_paths": {
                "original": str(previous_binary_path),
                "mutated": str(current_binary_path),
            },
        }

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

    def capture_structural_baseline(self, binary: Binary, function_address: int | None) -> dict[str, Any]:
        """Capture a lightweight baseline before mutation."""
        if self.mode == "off" or function_address in (None, 0):
            return {}

        detector = InvariantDetector(binary)
        try:
            invariants = detector.detect_all_invariants(function_address)
        except Exception as e:
            logger.debug(f"Failed to capture invariants for 0x{function_address:x}: {e}")
            invariants = []

        return {
            "function_address": function_address,
            "invariant_count": len(invariants),
            "invariants": [
                {
                    "type": inv.invariant_type.value,
                    "location": inv.location,
                    "description": inv.description,
                    "details": dict(inv.details),
                }
                for inv in invariants
            ],
        }

    def validate_mutation(self, binary: Binary, mutation: dict[str, Any]) -> ValidationOutcome:
        """Validate a single mutation record."""
        if self.mode == "off":
            return ValidationOutcome(validator_type="off", passed=True, scope="mutation")
        outcome = self._validate_structural_mutation(
            binary,
            mutation,
            validator_type=self.mode,
        )
        if self.mode == "symbolic":
            outcome.metadata.update(
                {
                    "symbolic_requested": True,
                    "symbolic_proven": False,
                    "symbolic_status": "structural-fallback",
                }
            )
        return outcome

    def validate_pass(self, binary: Binary, pass_result: dict[str, Any]) -> ValidationOutcome:
        """Validate all mutations produced by a pass."""
        if self.mode == "off":
            return ValidationOutcome(validator_type="off", passed=True, scope="pass")

        pass_name = pass_result.get("pass_name")
        mutations = pass_result.get("mutations", [])
        issues: list[ValidationIssue] = []

        for mutation in mutations:
            outcome = self.validate_mutation(binary, mutation)
            issues.extend(outcome.issues)
            mutation_metadata = mutation.setdefault("metadata", {})
            mutation_metadata["structural_validation"] = outcome.to_dict()
            mutation_metadata["validation_passed"] = outcome.passed

        result = ValidationOutcome(
            validator_type=self.mode,
            passed=not issues,
            scope="pass",
            issues=issues,
            metadata={
                "pass_name": pass_name,
                "mutations_checked": len(mutations),
            },
        )
        if self.mode == "symbolic":
            result.metadata.update(self._run_symbolic_precheck(binary, pass_result))
            bridge_module = import_module("r2morph.analysis.symbolic.angr_bridge")
            if pass_result.get("pass_name") in {
                "InstructionSubstitution",
                "NopInsertion",
                "RegisterSubstitution",
            }:
                result.metadata.update(self._compare_real_binary_regions(binary, pass_result, bridge_module))
                if result.metadata.get("symbolic_binary_check_performed"):
                    if result.metadata.get("symbolic_binary_equivalent"):
                        result.metadata["symbolic_status"] = "real-binary-observables-match"
                        result.metadata["symbolic_reason"] = (
                            "bounded real-binary symbolic effects matched for the mutated regions"
                        )
                    else:
                        result.metadata["symbolic_status"] = "real-binary-observable-mismatch"
                        result.metadata["symbolic_reason"] = (
                            "bounded real-binary symbolic effects diverged for the mutated regions"
                        )
            self._annotate_mutations_with_symbolic_metadata(pass_result, result.metadata)

        if self.check_abi:
            abi_issues = self._check_abi_violations(binary, pass_result)
            issues.extend(abi_issues)
            if abi_issues:
                result.issues.extend(abi_issues)
                result.passed = False
                result.metadata["abi_violations"] = len(abi_issues)

        return result

    def validate_abi(
        self, binary: Binary, function_address: int, mutation_regions: list[tuple[int, int]] | None = None
    ) -> dict[str, Any]:
        """
        Check ABI invariants for a function.

        Args:
            binary: Binary to check
            function_address: Function address
            mutation_regions: Optional list of mutated regions

        Returns:
            Dictionary with ABI validation results
        """
        if self._abi_checker is None:
            self._abi_checker = ABIChecker(binary)

        violations = self._abi_checker.check_all(function_address, mutation_regions)

        return {
            "passed": len(violations) == 0,
            "violations": [
                {
                    "type": v.violation_type.value,
                    "description": v.description,
                    "location": v.location,
                    "details": v.details,
                }
                for v in violations
            ],
            "violation_count": len(violations),
        }

    def _check_abi_violations(self, binary: Binary, pass_result: dict[str, Any]) -> list[ValidationIssue]:
        """Check for ABI violations in a pass."""
        issues: list[ValidationIssue] = []

        if self._abi_checker is None:
            self._abi_checker = ABIChecker(binary)

        mutations = pass_result.get("mutations", [])
        mutation_regions: list[tuple[int, int]] = []

        for mutation in mutations:
            start = mutation.get("start_address")
            end = mutation.get("end_address")
            if start is not None and end is not None:
                mutation_regions.append((start, end))

        functions = binary.get_functions() if hasattr(binary, "get_functions") else []
        for func in functions[:5]:
            func_addr = func.get("offset") or func.get("addr", 0)
            violations = self._abi_checker.check_all(func_addr, mutation_regions if mutation_regions else None)

            for v in violations:
                issues.append(
                    ValidationIssue(
                        validator="abi",
                        message=v.description,
                        address_range=(v.location, v.location + 8),
                        severity="warning",
                        evidence=v.details,
                    )
                )

        return issues
