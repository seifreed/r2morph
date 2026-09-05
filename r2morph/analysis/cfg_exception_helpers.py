"""Platform-specific CFG exception-edge detection helpers."""

from __future__ import annotations

import logging

from r2morph.analysis.cfg_models import BlockType, ControlFlowGraph, ExceptionEdge
from r2morph.analysis.exception_reader import ExceptionInfoReader
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
    try:
        frames = ExceptionInfoReader(binary).read_exception_frames()
        frame = frames.get(function_address)
        if frame is None:
            frame = next(
                (
                    candidate
                    for candidate in frames.values()
                    if candidate.function_start <= function_address < candidate.function_end
                ),
                None,
            )
        if frame is None:
            return []

        exception_edges: list[ExceptionEdge] = []
        for pad in frame.landing_pads:
            for block in cfg.blocks.values():
                if block.address == pad.address:
                    block.block_type = BlockType.LANDING_PAD
                    block.metadata["is_landing_pad"] = True
                    break
            source_address = pad.metadata.get("call_site_start", function_address)
            if not isinstance(source_address, int) or not frame.function_start <= source_address < frame.function_end:
                source_address = function_address
            exception_edges.append(
                ExceptionEdge(
                    from_address=source_address,
                    to_address=pad.address,
                    exception_type=pad.action.value,
                    landing_pad=pad.address,
                    action=pad.action.value,
                    metadata=dict(pad.metadata),
                )
            )
        return exception_edges
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.debug("Failed to detect ELF exception edges: %s", exc)
        return []


def detect_pe_exception_edges(binary: Binary, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:
    """Detect exception edges from PE .pdata metadata."""
    return []


def detect_macho_exception_edges(binary: Binary, cfg: ControlFlowGraph, function_address: int) -> list[ExceptionEdge]:
    """Detect exception edges from Mach-O __unwind_info metadata."""
    return []


__all__ = [
    "detect_elf_exception_edges",
    "detect_exception_edges",
    "detect_macho_exception_edges",
    "detect_pe_exception_edges",
]
