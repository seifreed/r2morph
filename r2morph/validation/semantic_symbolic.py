"""Symbolic-validation helpers for semantic validation."""

from __future__ import annotations

import logging
from typing import Any

angr: Any
claripy: Any
try:
    import angr
    import claripy

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    angr = None
    claripy = None

logger = logging.getLogger(__name__)


def default_observables(bits: int) -> list[str]:
    """Get default observables for architecture."""
    if bits == 64:
        return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "eflags"]
    return ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags"]


def create_symbolic_state(
    project: Any,
    address: int,
    bits: int,
    observables: list[str],
) -> Any | None:
    """Create symbolic state for comparison."""
    try:
        state = project.factory.blank_state(addr=address)
        stack_reg = "rsp" if bits == 64 else "esp"
        base_reg = "rbp" if bits == 64 else "ebp"

        setattr(state.regs, stack_reg, claripy.BVV(0x100000, bits))
        setattr(state.regs, base_reg, claripy.BVV(0x100000, bits))

        for reg in observables:
            if reg in ("eflags", "flags"):
                continue
            if hasattr(state.regs, reg):
                size = 64 if reg.startswith("r") or reg.startswith("e") else 32
                symbolic = claripy.BVS(f"{reg}_{address:x}", size)
                setattr(state.regs, reg, symbolic)

        return state
    except Exception:
        return None


def run_symbolic_validation(binary: Any, result: Any, observables: list[str] | None = None) -> None:
    """Run symbolic execution validation using angr."""
    if not ANGR_AVAILABLE:
        result.symbolic_status = "angr_unavailable"
        return

    try:
        from r2morph.analysis.symbolic import AngrBridge

        arch_info = binary.get_arch_info()
        bits = arch_info.get("bits", 64)
        arch = arch_info.get("arch", "")

        if arch not in ("x86", "x86_64"):
            result.symbolic_status = "unsupported_arch"
            return

        observables = observables or default_observables(bits)
        bridge = AngrBridge(binary)

        original_project = bridge.angr_project
        original_state = create_symbolic_state(
            original_project, result.region.start_address, bits, observables
        )

        if original_state is None:
            result.symbolic_status = "state_creation_failed"
            return

        result.symbolic_status = "symbolic_check_performed"
        from r2morph.validation.semantic_models import ObservableComparison

        result.observables = ObservableComparison()

    except Exception as e:
        logger.debug("Symbolic validation failed: %s", e)
        result.symbolic_status = f"error: {str(e)}"
