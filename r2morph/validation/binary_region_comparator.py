"""Real-binary region comparator extracted from SymbolicValidator (slice 3a).

Opens the real pre-pass and post-pass binaries, builds AngrBridge pairs
and symbolically steps each mutation region to compare register/stack/
memory-write effects. Imported lazily by SymbolicValidator.__init__
(composition root). Owns its own SymbolicScopeGate for the per-region
step-budget estimate.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


def _step_to_exit(
    state: Any,
    bridge: Any,
    resolved_addr: Any,
    region_width: int,
    region_exit_budget: int,
) -> tuple[Any, int, str | None, list[Any]]:
    """Step symbolic state until it exits the region. Returns (final, steps, error, trace)."""
    final, steps, error, trace = state, 0, None, [resolved_addr]
    for _ in range(region_exit_budget):
        addr = getattr(final, "addr", None)
        if addr is None or addr > resolved_addr + region_width - 1:
            break
        succ = list(bridge.angr_project.factory.successors(final, num_inst=1).flat_successors)
        if len(succ) != 1:
            error = "successor_count"
            break
        final = succ[0]
        steps += 1
        nxt = getattr(final, "addr", None)
        if nxt is not None:
            trace.append(nxt)
    else:
        error = "region_exit_budget_exhausted"
    return final, steps, error, trace


class BinaryRegionComparator:
    """Bounded real-binary symbolic comparison of mutated regions."""

    def __init__(self) -> None:
        from r2morph.validation.symbolic_scope_gate import SymbolicScopeGate

        self._scope_gate = SymbolicScopeGate()

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

        self._compare_register_states(original_final, mutated_final, compared_registers, _record)
        self._compare_stack_and_memory(original_final, mutated_final, stack_reg, region_report, _record)

    @staticmethod
    def _compare_register_states(
        original_final: Any,
        mutated_final: Any,
        compared_registers: list[str],
        record: Callable[[str], None],
    ) -> None:
        """Record register and eflags divergences between the two final states."""
        for reg_name in compared_registers:
            if not hasattr(original_final.regs, reg_name) or not hasattr(mutated_final.regs, reg_name):
                continue
            left = getattr(original_final.regs, reg_name)
            right = getattr(mutated_final.regs, reg_name)
            if original_final.solver.satisfiable(extra_constraints=[left != right]):
                record(reg_name)

        if hasattr(original_final.regs, "eflags") and hasattr(mutated_final.regs, "eflags"):
            if original_final.solver.satisfiable(
                extra_constraints=[original_final.regs.eflags != mutated_final.regs.eflags]
            ):
                record("eflags")

    def _compare_stack_and_memory(
        self,
        original_final: Any,
        mutated_final: Any,
        stack_reg: str,
        region_report: dict[str, Any],
        record: Callable[[str], None],
    ) -> None:
        """Record stack-pointer and memory-write divergences; expose write signatures."""
        original_stack = getattr(original_final.regs, stack_reg)
        mutated_stack = getattr(mutated_final.regs, stack_reg)
        if original_final.solver.satisfiable(extra_constraints=[original_stack != mutated_stack]):
            record("stack_delta")

        original_writes = self._collect_memory_write_signatures(original_final)
        mutated_writes = self._collect_memory_write_signatures(mutated_final)
        region_report["original_memory_writes"] = original_writes
        region_report["mutated_memory_writes"] = mutated_writes
        region_report["original_memory_write_count"] = len(original_writes)
        region_report["mutated_memory_write_count"] = len(mutated_writes)
        if original_writes != mutated_writes:
            record("memory_writes")

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
        from r2morph.analysis.symbolic.angr_bridge import AngrBridge

        with Binary(previous_binary_path, writable=False) as original_binary:
            original_bridge, error = self._create_original_bridge(original_binary, AngrBridge)
            if error is not None:
                return error
            mutated_bridge, error = self._create_mutated_bridge(binary, original_bridge, AngrBridge)
            if error is not None:
                return error
            angr_module = getattr(bridge_module, "angr", None)
            if angr_module is None:
                return {
                    "symbolic_binary_check_performed": False,
                    "symbolic_binary_reason": "angr module not available",
                }
            claripy = import_module("claripy")
            options = angr_module.options
            return (original_bridge, mutated_bridge, angr_module, claripy, options)

    def _create_original_bridge(
        self,
        original_binary: Binary,
        angr_bridge_cls: Any,
    ) -> tuple[Any, dict[str, Any] | None]:
        """Analyze the original binary and build its AngrBridge.

        Returns (bridge, None) on success or (None, error_dict).
        """
        try:
            original_binary.analyze("aa")
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as analyze_error:
            logger.warning(f"Failed to analyze original binary: {analyze_error}")
            return None, {
                "symbolic_binary_check_performed": False,
                "symbolic_binary_reason": f"Failed to analyze original binary: {analyze_error}",
            }
        try:
            return angr_bridge_cls(original_binary), None
        except Exception as bridge_error:  # AngrBridge init may raise any angr error
            logger.error(f"Failed to create original bridge: {bridge_error}")
            return None, {
                "symbolic_binary_check_performed": False,
                "symbolic_binary_reason": f"Failed to create original bridge: {bridge_error}",
            }

    def _create_mutated_bridge(
        self,
        binary: Binary,
        original_bridge: Any,
        angr_bridge_cls: Any,
    ) -> tuple[Any, dict[str, Any] | None]:
        """Build the mutated AngrBridge; close the original bridge on failure.

        Returns (bridge, None) on success or (None, error_dict).
        """
        try:
            return angr_bridge_cls(binary), None
        except Exception as bridge_error:  # AngrBridge init may raise any angr error
            if original_bridge and hasattr(original_bridge, "angr_project"):
                try:
                    original_bridge.angr_project.loader.close()
                except Exception as exc:
                    # Best-effort cleanup of the angr loader on the error
                    # path; a close failure here must not mask the
                    # original bridge_error reported below.
                    logger.debug("angr loader close failed during cleanup: %s", exc)
            logger.error(f"Failed to create mutated bridge: {bridge_error}")
            return None, {
                "symbolic_binary_check_performed": False,
                "symbolic_binary_reason": f"Failed to create mutated bridge: {bridge_error}",
            }

    def _build_state_pair(
        self,
        original_bridge: Any,
        mutated_bridge: Any,
        original_binary: Binary,
        claripy: Any,
        options: Any,
        resolved_original: Any,
        resolved_mutated: Any,
        start: int,
    ) -> tuple[Any, Any, list[str], str]:
        """Build seeded original/mutated blank states.

        Returns (original_state, mutated_state, compared_registers, stack_reg).
        """
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
        return original_state, mutated_state, compared_registers, stack_reg

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

        original_state, mutated_state, compared_registers, stack_reg = self._build_state_pair(
            original_bridge,
            mutated_bridge,
            original_binary,
            claripy,
            options,
            resolved_original,
            resolved_mutated,
            start,
        )

        original_final, original_steps, original_exit_error, original_trace_addresses = _step_to_exit(
            original_state,
            original_bridge,
            resolved_original,
            region_width,
            region_exit_budget,
        )
        mutated_final, mutated_steps, mutated_exit_error, mutated_trace_addresses = _step_to_exit(
            mutated_state,
            mutated_bridge,
            resolved_mutated,
            region_width,
            region_exit_budget,
        )

        region_report = self._build_region_report(
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

    def _build_region_report(
        self,
        mutation: dict[str, Any],
        resolved_original: Any,
        resolved_mutated: Any,
        step_budget: int,
        region_exit_budget: int,
        original_steps: int,
        mutated_steps: int,
        original_trace_addresses: list[Any],
        mutated_trace_addresses: list[Any],
        compared_registers: list[str],
    ) -> dict[str, Any]:
        """Build the region-report skeleton (pre-finalization)."""
        return {
            "start_address": mutation["start_address"],
            "end_address": mutation["end_address"],
            "original_loaded_address": resolved_original,
            "mutated_loaded_address": resolved_mutated,
            "step_budget": step_budget,
            "region_exit_budget": region_exit_budget,
            "step_strategy": "region-exit",
            "original_region_exit_steps": original_steps,
            "mutated_region_exit_steps": mutated_steps,
            "original_trace_addresses": original_trace_addresses,
            "mutated_trace_addresses": mutated_trace_addresses,
            "registers_checked": list(compared_registers) + ["eflags", "stack_delta"],
            "mismatches": [],
        }

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
            bridge_result = self._setup_symbolic_bridges(
                binary,
                previous_binary_path,
                current_binary_path,
                bridge_module,
            )
            if isinstance(bridge_result, dict):
                return bridge_result
            original_bridge, mutated_bridge, angr_module, claripy, options = bridge_result

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
        except Exception as e:  # angr symbolic comparison may raise any exception type
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
                except Exception as e:  # best-effort cleanup
                    cleanup_errors.append(f"original: {e}")
                    logger.warning(f"Error closing original angr project: {e}")
            if mutated_bridge is not None and hasattr(mutated_bridge, "angr_project"):
                try:
                    if hasattr(mutated_bridge.angr_project, "loader"):
                        mutated_bridge.angr_project.loader.close()
                except Exception as e:  # best-effort cleanup
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
                else (
                    "bounded real-binary symbolic effects diverged"
                    if compared_regions
                    else "no eligible regions for real-binary symbolic comparison"
                )
            ),
            "symbolic_binary_regions": compared_regions,
            "symbolic_binary_mismatches": mismatches,
            "symbolic_binary_paths": {
                "original": str(previous_binary_path),
                "mutated": str(current_binary_path),
            },
        }
