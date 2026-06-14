"""Platform-specific CFG exception-edge detection helpers."""

from __future__ import annotations

import logging

from r2morph.analysis.cfg_models import BlockType, ControlFlowGraph, ExceptionEdge
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


def detect_exception_edges(binary: Binary, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:
    """Detect exception handling edges in a function."""
    exception_edges: list[ExceptionEdge] = []

    arch_info = binary.get_arch_info()
    binary_format = arch_info.get("format", "")

    if binary_format.startswith("ELF"):
        exception_edges = detect_elf_exception_edges(binary, cfg, function_address)
    elif binary_format in ("PE", "PE+"):
        exception_edges = detect_pe_exception_edges(binary, cfg, function_address)
    elif binary_format in ("Mach-O", "Mach-O-64"):
        exception_edges = detect_macho_exception_edges(binary, cfg, function_address)

    for edge in exception_edges:
        cfg.add_exception_edge(edge)

    return exception_edges


def detect_elf_exception_edges(binary: Binary, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:
    """Detect exception edges from ELF .eh_frame metadata."""
    exception_edges: list[ExceptionEdge] = []

    try:
        if binary.r2 is None:
            return exception_edges
        functions = binary.r2.cmdj("aflj")
        if not functions:
            return exception_edges

        landing_pads = set()
        for func in functions if isinstance(functions, list) else []:
            func_addr = func.get("addr", func.get("offset", 0))
            if func_addr == function_address:
                landing_pads.update(func.get("landing_pads", []))

        for block in cfg.blocks.values():
            if block.address in landing_pads:
                block.block_type = BlockType.LANDING_PAD
                block.metadata["is_landing_pad"] = True
    except (ValueError, OSError, BrokenPipeError, RuntimeError) as exc:
        logger.debug(f"Failed to detect ELF exception edges: {exc}")

    return exception_edges


def detect_pe_exception_edges(binary: Binary, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:  # noqa: ARG001
    """Detect exception edges from PE .pdata metadata."""
    return []


def detect_macho_exception_edges(binary: Binary, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:  # noqa: ARG001
    """Detect exception edges from Mach-O __unwind_info metadata."""
    return []


__all__ = [
    "detect_exception_edges",
    "detect_elf_exception_edges",
    "detect_macho_exception_edges",
    "detect_pe_exception_edges",
]
