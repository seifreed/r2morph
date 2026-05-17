"""
Validation management for mutation passes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from dataclasses import asdict, dataclass, field
from importlib import import_module
from typing import Any

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

    def __init__(self, mode: str = "structural", check_abi: bool = False) -> None:
        from r2morph.validation.abi_validator import AbiValidator
        from r2morph.validation.structural_validator import StructuralValidator
        from r2morph.validation.symbolic_validator import SymbolicValidator

        self.mode = mode
        self.check_abi = check_abi
        self._structural_validator = StructuralValidator()
        self._abi_validator = AbiValidator()
        self._symbolic_validator = SymbolicValidator()

    def _collect_memory_write_signatures(self, state: Any) -> list[str]:
        """Collect a compact, best-effort signature of memory writes from an angr state."""
        return self._symbolic_validator._collect_memory_write_signatures(state)

    def _validate_structural_mutation(
        self,
        binary: Binary,
        mutation: dict[str, Any],
        *,
        validator_type: str,
    ) -> ValidationOutcome:
        """Validate a single mutation using structural checks."""
        return self._structural_validator.validate_mutation(binary, mutation, validator_type=validator_type)

    def _supports_symbolic_scope(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
    ) -> tuple[bool, str, dict[str, Any]]:
        """Check whether the current pass is inside the experimental symbolic scope."""
        return self._symbolic_validator._supports_symbolic_scope(binary, pass_result)

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
        except Exception as e:  # angr/claripy backend may raise any exception type
            payload["symbolic_status"] = "backend-error"
            payload["symbolic_reason"] = str(e)
            return payload

    def _estimate_symbolic_region_steps(
        self,
        pass_name: str,
        mutation: dict[str, Any],
    ) -> int:
        """Estimate a small but useful symbolic step budget for a mutated region."""
        return self._symbolic_validator._estimate_symbolic_region_steps(pass_name, mutation)

    def _build_instruction_substitution_symbolic_hint(self, pass_result: dict[str, Any]) -> dict[str, Any]:
        """Add a narrow semantic hint for instruction substitutions from known equivalence groups."""
        return self._symbolic_validator._build_instruction_substitution_symbolic_hint(pass_result)

    def _compare_instruction_substitution_observables(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare a small set of observable register/flag effects for InstructionSubstitution snippets."""
        return self._symbolic_validator._compare_instruction_substitution_observables(
            binary, pass_result, bridge_module
        )

    def _compare_instruction_substitution_transition(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare successor address and stack delta for supported substitution snippets."""
        return self._symbolic_validator._compare_instruction_substitution_transition(binary, pass_result, bridge_module)

    def _setup_symbolic_bridges(
        self,
        binary: Binary,
        previous_binary_path: Path,
        current_binary_path: Path,
        bridge_module: Any,
    ) -> dict[str, Any] | tuple[Any, Any, Any, Any, Any]:
        """Create AngrBridge for original and mutated binaries.

        Returns (original_bridge, mutated_bridge, angr_module, claripy, options)
        on success, or a failure dict on error.
        """
        return self._symbolic_validator._setup_symbolic_bridges(
            binary, previous_binary_path, current_binary_path, bridge_module
        )

    def _compare_single_region(
        self,
        mutation: dict[str, Any],
        original_bridge: Any,
        mutated_bridge: Any,
        original_binary: Binary,
        angr_module: Any,
        claripy: Any,
        options: Any,
        pass_name: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Compare symbolic effects for a single mutation region.

        Returns (region_report, mismatches) for this region.
        """
        return self._symbolic_validator._compare_single_region(
            mutation,
            original_bridge,
            mutated_bridge,
            original_binary,
            angr_module,
            claripy,
            options,
            pass_name,
        )

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
        self._symbolic_validator._check_observables(
            region_report,
            mismatches,
            mutation,
            original_final,
            mutated_final,
            compared_registers,
            stack_reg,
        )

    def _compare_real_binary_regions(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare bounded symbolic effects on the real pre-pass and post-pass binaries."""
        return self._symbolic_validator._compare_real_binary_regions(binary, pass_result, bridge_module)

    def _annotate_mutations_with_symbolic_metadata(
        self,
        pass_result: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        """Attach pass-level symbolic evidence to each eligible mutation record."""
        self._symbolic_validator._annotate_mutations_with_symbolic_metadata(pass_result, metadata)

    def capture_structural_baseline(self, binary: Binary, function_address: int | None) -> dict[str, Any]:
        """Capture a lightweight baseline before mutation."""
        return self._structural_validator.capture_baseline(binary, function_address, mode=self.mode)

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
        return self._abi_validator.validate(binary, function_address, mutation_regions)

    def _check_abi_violations(self, binary: Binary, pass_result: dict[str, Any]) -> list[ValidationIssue]:
        """Check for ABI violations in a pass."""
        return self._abi_validator.collect_violations(binary, pass_result)
