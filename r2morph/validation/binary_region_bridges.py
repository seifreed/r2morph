"""Bridge and runtime helpers for bounded real-binary region comparison."""

from __future__ import annotations

import logging
from importlib import import_module
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


def step_to_exit(
    state: Any,
    bridge: Any,
    resolved_addr: Any,
    region_width: int,
    region_exit_budget: int,
) -> tuple[Any, int, str | None, list[Any]]:
    """Step symbolic state until it exits the region."""
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


def build_state_pair(
    original_bridge: Any,
    mutated_bridge: Any,
    original_binary: Binary,
    claripy: Any,
    options: Any,
    resolved_original: Any,
    resolved_mutated: Any,
    start: int,
) -> tuple[Any, Any, list[str], str]:
    """Build seeded original/mutated blank states."""
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


def validate_binary_paths(binary: Binary, pass_result: dict[str, Any]) -> tuple[Path, Path] | dict[str, Any]:
    """Resolve the pre-pass and post-pass artifact paths or a failure payload."""
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
    return previous_binary_path, current_binary_path


def setup_symbolic_bridges(
    binary: Binary,
    previous_binary_path: Path,
    current_binary_path: Path,
    bridge_module: Any,
) -> dict[str, Any] | tuple[Any, Any, Any, Any, Any]:
    """Create AngrBridge for original and mutated binaries."""
    from r2morph.analysis.symbolic.angr_bridge import AngrBridge

    with Binary(previous_binary_path, writable=False) as original_binary:
        original_bridge, error = _create_original_bridge(original_binary, AngrBridge)
        if error is not None:
            return error
        mutated_bridge, error = _create_mutated_bridge(binary, original_bridge, AngrBridge)
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


def release_bridges(original_bridge: Any, mutated_bridge: Any) -> None:
    """Best-effort release of angr loader resources for both bridges."""
    cleanup_errors = []
    if original_bridge is not None and hasattr(original_bridge, "angr_project"):
        try:
            if hasattr(original_bridge.angr_project, "loader"):
                original_bridge.angr_project.loader.close()
        except Exception as e:  # best-effort cleanup
            cleanup_errors.append(f"original: {e}")
            logger.warning("Error closing original angr project: %s", e)
    if mutated_bridge is not None and hasattr(mutated_bridge, "angr_project"):
        try:
            if hasattr(mutated_bridge.angr_project, "loader"):
                mutated_bridge.angr_project.loader.close()
        except Exception as e:  # best-effort cleanup
            cleanup_errors.append(f"mutated: {e}")
            logger.warning("Error closing mutated angr project: %s", e)
    if cleanup_errors:
        logger.debug("Cleanup errors during angr resource release: %s", cleanup_errors)


def _create_original_bridge(
    original_binary: Binary,
    angr_bridge_cls: Any,
) -> tuple[Any, dict[str, Any] | None]:
    """Analyze the original binary and build its AngrBridge."""
    try:
        original_binary.analyze("aa")
    except (ValueError, OSError, BrokenPipeError, RuntimeError) as analyze_error:
        logger.warning("Failed to analyze original binary: %s", analyze_error)
        return None, {
            "symbolic_binary_check_performed": False,
            "symbolic_binary_reason": f"Failed to analyze original binary: {analyze_error}",
        }
    try:
        return angr_bridge_cls(original_binary), None
    except Exception as bridge_error:  # AngrBridge init may raise any angr error
        logger.error("Failed to create original bridge: %s", bridge_error)
        return None, {
            "symbolic_binary_check_performed": False,
            "symbolic_binary_reason": f"Failed to create original bridge: {bridge_error}",
        }


def _create_mutated_bridge(
    binary: Binary,
    original_bridge: Any,
    angr_bridge_cls: Any,
) -> tuple[Any, dict[str, Any] | None]:
    """Build the mutated AngrBridge; close the original bridge on failure."""
    try:
        return angr_bridge_cls(binary), None
    except Exception as bridge_error:  # AngrBridge init may raise any angr error
        if original_bridge and hasattr(original_bridge, "angr_project"):
            try:
                original_bridge.angr_project.loader.close()
            except Exception as exc:
                logger.debug("angr loader close failed during cleanup: %s", exc)
        logger.error("Failed to create mutated bridge: %s", bridge_error)
        return None, {
            "symbolic_binary_check_performed": False,
            "symbolic_binary_reason": f"Failed to create mutated bridge: {bridge_error}",
        }


__all__ = [
    "build_state_pair",
    "release_bridges",
    "setup_symbolic_bridges",
    "step_to_exit",
    "validate_binary_paths",
]
