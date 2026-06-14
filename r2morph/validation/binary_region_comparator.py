"""Real-binary region comparator extracted from SymbolicValidator (slice 3a).

Opens the real pre-pass and post-pass binaries, builds AngrBridge pairs
and symbolically steps each mutation region to compare register/stack/
memory-write effects. Imported lazily by SymbolicValidator.__init__
(composition root). Owns its own SymbolicScopeGate for the per-region
step-budget estimate.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.binary_region_bridges import (
    build_state_pair,
    release_bridges,
    setup_symbolic_bridges,
    step_to_exit,
    validate_binary_paths,
)
from r2morph.validation.binary_region_comparator_observables import check_observables
from r2morph.validation.binary_region_comparator_results import (
    build_binary_comparison_result,
    build_region_report,
)

logger = logging.getLogger(__name__)


class BinaryRegionComparator:
    """Bounded real-binary symbolic comparison of mutated regions."""

    def __init__(self) -> None:
        from r2morph.validation.symbolic_scope_gate import SymbolicScopeGate

        self._scope_gate = SymbolicScopeGate()

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
        check_observables(
            region_report,
            mismatches,
            mutation,
            original_final,
            mutated_final,
            compared_registers,
            stack_reg,
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
        mismatches: list[dict[str, Any]] = []
        start = mutation["start_address"]
        end = mutation["end_address"]
        step_budget = self._scope_gate._estimate_symbolic_region_steps(pass_name, mutation)
        region_width = max(1, end - start + 1)
        region_exit_budget = max(step_budget * 2, region_width + 1)
        resolved_original = original_bridge.resolve_loaded_address(start)
        resolved_mutated = mutated_bridge.resolve_loaded_address(start)
        if resolved_original is None or resolved_mutated is None:
            logger.warning(f"Failed to resolve loaded address for mutation at 0x{start:x}")
            return {"skipped": True, "reason": "resolve_failed"}, []

        original_state, mutated_state, compared_registers, stack_reg = build_state_pair(
            original_bridge,
            mutated_bridge,
            original_binary,
            claripy,
            options,
            resolved_original,
            resolved_mutated,
            start,
        )

        original_final, original_steps, original_exit_error, original_trace_addresses = step_to_exit(
            original_state,
            original_bridge,
            resolved_original,
            region_width,
            region_exit_budget,
        )
        mutated_final, mutated_steps, mutated_exit_error, mutated_trace_addresses = step_to_exit(
            mutated_state,
            mutated_bridge,
            resolved_mutated,
            region_width,
            region_exit_budget,
        )

        region_report = build_region_report(
            mutation,
            resolved_original,
            resolved_mutated,
            step_budget,
            region_exit_budget,
            original_steps,
            mutated_steps,
            original_trace_addresses,
            mutated_trace_addresses,
            compared_registers,
        )
        return self._finalize_region_outcome(
            region_report,
            mismatches,
            mutation,
            original_exit_error,
            mutated_exit_error,
            original_final,
            mutated_final,
            compared_registers,
            stack_reg,
        )

    def _finalize_region_outcome(
        self,
        region_report: dict[str, Any],
        mismatches: list[dict[str, Any]],
        mutation: dict[str, Any],
        original_exit_error: str | None,
        mutated_exit_error: str | None,
        original_final: Any,
        mutated_final: Any,
        compared_registers: list[str],
        stack_reg: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Apply the exit-error or observable-comparison outcome to the region report."""
        if original_exit_error or mutated_exit_error:
            region_report["step_strategy"] = "region-exit-fallback-budget"
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
            return region_report, mismatches

        region_report["original_region_exit_address"] = getattr(original_final, "addr", None)
        region_report["mutated_region_exit_address"] = getattr(mutated_final, "addr", None)
        region_report["control_flow_observables"] = ["region_exit_address", "region_exit_steps"]

        self._check_observables(
            region_report,
            mismatches,
            mutation,
            original_final,
            mutated_final,
            compared_registers,
            stack_reg,
        )
        return region_report, mismatches

    def _compare_real_binary_regions(
        self,
        binary: Binary,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        """Compare bounded symbolic effects on the real pre-pass and post-pass binaries."""
        validated = validate_binary_paths(binary, pass_result)
        if isinstance(validated, dict):
            return validated
        previous_binary_path, current_binary_path = validated

        original_bridge = None
        mutated_bridge = None
        try:
            bridge_result = setup_symbolic_bridges(
                binary,
                previous_binary_path,
                current_binary_path,
                bridge_module,
            )
            if isinstance(bridge_result, dict):
                return bridge_result
            original_bridge, mutated_bridge, angr_module, claripy, options = bridge_result
            compared_regions, mismatches = self._run_region_comparison_loop(
                previous_binary_path,
                original_bridge,
                mutated_bridge,
                angr_module,
                claripy,
                options,
                pass_result,
            )
        except Exception as e:  # angr symbolic comparison may raise any exception type
            return {
                "symbolic_binary_check_performed": False,
                "symbolic_binary_reason": f"real binary symbolic comparison failed: {e}",
            }
        finally:
            release_bridges(original_bridge, mutated_bridge)

        return build_binary_comparison_result(
            compared_regions, mismatches, previous_binary_path, current_binary_path
        )

    def _run_region_comparison_loop(
        self,
        previous_binary_path: Path,
        original_bridge: Any,
        mutated_bridge: Any,
        angr_module: Any,
        claripy: Any,
        options: Any,
        pass_result: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Symbolically compare every mutation region on the pre-pass binary."""
        compared_regions = []
        mismatches = []
        pass_name = pass_result.get("pass_name", "")
        with Binary(previous_binary_path, writable=False) as original_binary:
            original_binary.analyze("aa")
            for mutation in pass_result.get("mutations", []):
                result = self._compare_single_region(
                    mutation,
                    original_bridge,
                    mutated_bridge,
                    original_binary,
                    angr_module,
                    claripy,
                    options,
                    pass_name,
                )
                region_report, region_mismatches = result
                if region_report is None:
                    continue
                compared_regions.append(region_report)
                mismatches.extend(region_mismatches)
        return compared_regions, mismatches
