"""Symbolic precheck flow for pass-level symbolic validation."""

from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.manager import _parse_address


def run_symbolic_precheck(
    binary: Binary,
    pass_result: dict[str, Any],
    *,
    supports_scope: Callable[[Binary, dict[str, Any]], tuple[bool, str, dict[str, Any]]],
    estimate_steps: Callable[[str, dict[str, Any]], int],
    build_hint: Callable[[dict[str, Any]], dict[str, Any]],
    compare_observables: Callable[[Binary, dict[str, Any], Any], dict[str, Any]],
    compare_transition: Callable[[Binary, dict[str, Any], Any], dict[str, Any]],
    import_module_fn: Callable[[str], Any] = import_module,
) -> dict[str, Any]:
    """Run a bounded symbolic precheck for the experimental mode."""
    supported, payload = _init_scope_payload(binary, pass_result, supports_scope)
    if not supported:
        return payload

    try:
        bridge_module = import_module_fn("r2morph.analysis.symbolic.angr_bridge")
        if not getattr(bridge_module, "ANGR_AVAILABLE", False):
            payload["symbolic_status"] = "backend-unavailable"
            payload["symbolic_reason"] = "angr is not installed"
            return payload

        bridge = bridge_module.AngrBridge(binary)
        initialized, stepped_regions, total_flat, total_unsat, step_error = _execute_bounded_steps(
            bridge, pass_result, estimate_steps
        )
        _record_bounded_step_results(
            payload, pass_result, initialized, stepped_regions, total_flat, total_unsat, build_hint
        )
        _finalize_precheck_status(
            payload,
            binary,
            pass_result,
            bridge_module,
            step_error,
            compare_observables=compare_observables,
            compare_transition=compare_transition,
        )
        return payload
    except Exception as e:  # angr/claripy backend may raise any exception type
        payload["symbolic_status"] = "backend-error"
        payload["symbolic_reason"] = str(e)
        return payload


def _init_scope_payload(
    binary: Binary,
    pass_result: dict[str, Any],
    supports_scope: Callable[[Binary, dict[str, Any]], tuple[bool, str, dict[str, Any]]],
) -> tuple[bool, dict[str, Any]]:
    """Build the base payload and signal whether the symbolic scope is supported."""
    supported, reason, metadata = supports_scope(binary, pass_result)
    payload = {
        "symbolic_requested": True,
        "symbolic_proven": False,
        **metadata,
    }
    if not supported:
        payload["symbolic_status"] = reason
        payload["symbolic_reason"] = "falling back to structural validation"
    return supported, payload


def _step_one_mutation(
    bridge: Any,
    mutation: dict[str, Any],
    pass_name: str,
    estimate_steps: Callable[[str, dict[str, Any]], int],
) -> tuple[list[int] | None, dict[str, Any] | None, str | None]:
    """Symbolically step a single mutation region."""
    start = _parse_address(mutation["start_address"])
    end = _parse_address(mutation["end_address"])
    state = bridge.create_symbolic_state(start)
    if state is None:
        return None, None, f"failed to initialize symbolic state at 0x{start:x}"

    step_budget = estimate_steps(pass_name, mutation)
    try:
        successors = bridge.angr_project.factory.successors(state, num_inst=step_budget)
    except Exception as e:  # angr may raise any exception type during symbolic execution
        return [start, end], None, f"bounded symbolic step failed at 0x{start:x}: {e}"

    flat_successors = list(getattr(successors, "flat_successors", []))
    unsat_successors = list(getattr(successors, "unsat_successors", []))
    successor_addrs = sorted({succ.addr for succ in flat_successors if getattr(succ, "addr", None) is not None})
    region = {
        "start_address": start,
        "end_address": end,
        "flat_successors": len(flat_successors),
        "unsat_successors": len(unsat_successors),
        "successor_addresses": successor_addrs,
        "step_budget": step_budget,
    }
    return [start, end], region, None


def _execute_bounded_steps(
    bridge: Any,
    pass_result: dict[str, Any],
    estimate_steps: Callable[[str, dict[str, Any]], int],
) -> tuple[list[list[int]], list[dict[str, Any]], int, int, str | None]:
    """Run one bounded symbolic step per mutation region, accumulating results."""
    initialized: list[list[int]] = []
    stepped_regions: list[dict[str, Any]] = []
    total_flat_successors = 0
    total_unsat_successors = 0
    step_error: str | None = None
    pass_name = pass_result.get("pass_name", "")
    for mutation in pass_result.get("mutations", []):
        initialized_entry, region, error = _step_one_mutation(bridge, mutation, pass_name, estimate_steps)
        if initialized_entry is not None:
            initialized.append(initialized_entry)
        if region is not None:
            stepped_regions.append(region)
            total_flat_successors += region["flat_successors"]
            total_unsat_successors += region["unsat_successors"]
        if error is not None:
            step_error = error
            break
    return initialized, stepped_regions, total_flat_successors, total_unsat_successors, step_error


def _record_bounded_step_results(
    payload: dict[str, Any],
    pass_result: dict[str, Any],
    initialized: list[list[int]],
    stepped_regions: list[dict[str, Any]],
    total_flat_successors: int,
    total_unsat_successors: int,
    build_hint: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    """Record the bounded-step accumulators and substitution hint into the payload."""
    payload["symbolic_status"] = "bounded-step-passed"
    payload["symbolic_reason"] = "symbolic backend initialized and executed one bounded step per mutation region"
    payload["symbolic_initialized_regions"] = initialized
    payload["symbolic_step_count"] = len(stepped_regions)
    payload["symbolic_flat_successors"] = total_flat_successors
    payload["symbolic_unsat_successors"] = total_unsat_successors
    payload["symbolic_stepped_regions"] = stepped_regions
    payload.update(build_hint(pass_result))


def _resolve_shellcode_equivalence(
    payload: dict[str, Any],
    binary: Binary,
    pass_result: dict[str, Any],
    bridge_module: Any,
    compare_observables: Callable[[Binary, dict[str, Any], Any], dict[str, Any]],
    compare_transition: Callable[[Binary, dict[str, Any], Any], dict[str, Any]],
    *,
    match_status: str,
    match_reason: str,
    mismatch_status: str,
    mismatch_reason: str,
) -> None:
    """Run shellcode observable/transition checks and map them to a status."""
    payload.update(compare_observables(binary, pass_result, bridge_module))
    payload.update(compare_transition(binary, pass_result, bridge_module))
    if payload.get("symbolic_observable_check_performed"):
        transition_ok = payload.get("symbolic_transition_equivalent", True)
        if payload.get("symbolic_observable_equivalent") and transition_ok:
            payload["symbolic_status"] = match_status
            payload["symbolic_reason"] = match_reason
        else:
            payload["symbolic_status"] = mismatch_status
            payload["symbolic_reason"] = mismatch_reason


def _finalize_precheck_status(
    payload: dict[str, Any],
    binary: Binary,
    pass_result: dict[str, Any],
    bridge_module: Any,
    step_error: str | None,
    *,
    compare_observables: Callable[[Binary, dict[str, Any], Any], dict[str, Any]],
    compare_transition: Callable[[Binary, dict[str, Any], Any], dict[str, Any]],
) -> None:
    """Set the terminal symbolic status, including shellcode fallback checks."""
    if step_error is not None:
        payload["symbolic_status"] = (
            "state-init-failed" if step_error.startswith("failed to initialize") else "step-failed"
        )
        payload["symbolic_reason"] = step_error
        if payload.get("symbolic_semantic_hint_supported"):
            _resolve_shellcode_equivalence(
                payload,
                binary,
                pass_result,
                bridge_module,
                compare_observables,
                compare_transition,
                match_status="shellcode-observables-match",
                match_reason="binary symbolic step failed but shellcode observable/transition checks matched",
                mismatch_status="shellcode-observable-mismatch",
                mismatch_reason="binary symbolic step failed and shellcode observable or transition checks diverged",
            )
        return
    if payload.get("symbolic_semantic_hint_supported"):
        payload["symbolic_status"] = "bounded-step-known-equivalence"
        payload["symbolic_reason"] = (
            "symbolic bounded step passed and substitutions map to a known equivalence group"
        )
        _resolve_shellcode_equivalence(
            payload,
            binary,
            pass_result,
            bridge_module,
            compare_observables,
            compare_transition,
            match_status="bounded-step-observables-match",
            match_reason="bounded symbolic step passed and observable/transition effects matched",
            mismatch_status="bounded-step-observable-mismatch",
            mismatch_reason="bounded symbolic step passed but observable or transition effects diverged",
        )
